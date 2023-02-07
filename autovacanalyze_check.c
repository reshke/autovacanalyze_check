/*-------------------------------------------------------------------------
 *
 * autovacanalyze_check.c
 *		Check which tables needs vacuum or analyze
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include <signal.h>
#include <sys/time.h>
#include <unistd.h>

#include "funcapi.h"
#include "access/heapam.h"
#include "access/htup_details.h"
#include "access/multixact.h"
#include "access/reloptions.h"
#if PG_VERSION_NUM >= 120000
#include "access/tableam.h"
#endif
#include "access/transam.h"
#include "access/xact.h"
#include "catalog/dependency.h"
#include "catalog/namespace.h"
#include "catalog/pg_database.h"
#include "commands/dbcommands.h"
#include "commands/vacuum.h"
#include "lib/ilist.h"
#include "libpq/pqsignal.h"
#include "miscadmin.h"
#include "nodes/makefuncs.h"
#include "pgstat.h"
#include "postmaster/autovacuum.h"
#include "postmaster/fork_process.h"
#if PG_VERSION_NUM >= 130000
#include "postmaster/interrupt.h"
#endif
#include "postmaster/postmaster.h"
#include "storage/bufmgr.h"
#include "storage/ipc.h"
#include "storage/latch.h"
#include "storage/lmgr.h"
#include "storage/pmsignal.h"
#include "storage/proc.h"
#include "storage/procsignal.h"
#include "storage/sinvaladt.h"
#include "storage/smgr.h"
#include "catalog/pg_class.h"
#include "utils/rel.h"
#include "tcop/tcopprot.h"
#include "utils/fmgroids.h"
#include "utils/fmgrprotos.h"
#include "utils/lsyscache.h"
#include "utils/memutils.h"
#include "utils/ps_status.h"
#include "utils/rel.h"
#include "utils/snapmgr.h"
#include "utils/syscache.h"
#include "utils/timeout.h"
#include "utils/timestamp.h"


typedef struct vacanalyze_meta {
	Oid oid;
	bool need_analyze;
	bool need_vacuum;
} vacanalyze_meta;

PG_MODULE_MAGIC;

PG_FUNCTION_INFO_V1(autovacanalyze_check_internal);

/*
 * Helper function to construct whichever TupleDesc we need for a particular
 * call.
 */
static TupleDesc
autovacananlyze_check_tupdesc()
{
	TupleDesc	tupdesc;
	AttrNumber	maxattr = 3;

#if PG_VERSION_NUM >= 120000
	tupdesc = CreateTemplateTupleDesc(maxattr);
#else
	tupdesc = CreateTemplateTupleDesc(maxattr, true);
#endif
	TupleDescInitEntry(tupdesc, 1, "relation_oid", OIDOID, -1, 0);
	TupleDescInitEntry(tupdesc, 2, "need_vacuum", BOOLOID, -1, 0);
	TupleDescInitEntry(tupdesc, 3, "need_analyze", BOOLOID, -1, 0);

	return BlessTupleDesc(tupdesc);
}


/* relation_needs_vacanalyze & extract_autovac_opts from REL_15_STABLE code */


/*
 * extract_autovac_opts
 *
 * Given a relation's pg_class tuple, return the AutoVacOpts portion of
 * reloptions, if set; otherwise, return NULL.
 *
 * Note: callers do not have a relation lock on the table at this point,
 * so the table could have been dropped, and its catalog rows gone, after
 * we acquired the pg_class row.  If pg_class had a TOAST table, this would
 * be a risk; fortunately, it doesn't.
 */
static AutoVacOpts *
extract_autovac_opts(HeapTuple tup, TupleDesc pg_class_desc)
{
	bytea	   *relopts;
	AutoVacOpts *av;

	Assert(((Form_pg_class) GETSTRUCT(tup))->relkind == RELKIND_RELATION ||
		   ((Form_pg_class) GETSTRUCT(tup))->relkind == RELKIND_MATVIEW ||
		   ((Form_pg_class) GETSTRUCT(tup))->relkind == RELKIND_TOASTVALUE);

	relopts = extractRelOptions(tup, pg_class_desc, NULL);
	if (relopts == NULL)
		return NULL;

	av = palloc(sizeof(AutoVacOpts));
	memcpy(av, &(((StdRdOptions *) relopts)->autovacuum), sizeof(AutoVacOpts));
	pfree(relopts);

	return av;
}


/*
 * relation_needs_vacanalyze
 *
 * Check whether a relation needs to be vacuumed or analyzed; return each into
 * "dovacuum" and "doanalyze", respectively.  Also return whether the vacuum is
 * being forced because of Xid or multixact wraparound.
 *
 * relopts is a pointer to the AutoVacOpts options (either for itself in the
 * case of a plain table, or for either itself or its parent table in the case
 * of a TOAST table), NULL if none; tabentry is the pgstats entry, which can be
 * NULL.
 *
 * A table needs to be vacuumed if the number of dead tuples exceeds a
 * threshold.  This threshold is calculated as
 *
 * threshold = vac_base_thresh + vac_scale_factor * reltuples
 *
 * For analyze, the analysis done is that the number of tuples inserted,
 * deleted and updated since the last analyze exceeds a threshold calculated
 * in the same fashion as above.  Note that the cumulative stats system stores
 * the number of tuples (both live and dead) that there were as of the last
 * analyze.  This is asymmetric to the VACUUM case.
 *
 * We also force vacuum if the table's relfrozenxid is more than freeze_max_age
 * transactions back, and if its relminmxid is more than
 * multixact_freeze_max_age multixacts back.
 *
 * A table whose autovacuum_enabled option is false is
 * automatically skipped (unless we have to vacuum it due to freeze_max_age).
 * Thus autovacuum can be disabled for specific tables. Also, when the cumulative
 * stats system does not have data about a table, it will be skipped.
 *
 * A table whose vac_base_thresh value is < 0 takes the base value from the
 * autovacuum_vacuum_threshold GUC variable.  Similarly, a vac_scale_factor
 * value < 0 is substituted with the value of
 * autovacuum_vacuum_scale_factor GUC variable.  Ditto for analyze.
 */
static void
relation_needs_vacanalyze(Oid relid,
						  AutoVacOpts *relopts,
						  Form_pg_class classForm,
						  PgStat_StatTabEntry *tabentry,
						  int effective_multixact_freeze_max_age,
 /* output params below */
						  bool *dovacuum,
						  bool *doanalyze,
						  bool *wraparound)
{
	bool		force_vacuum;
	bool		av_enabled;
	float4		reltuples;		/* pg_class.reltuples */

	/* constants from reloptions or GUC variables */
	int			vac_base_thresh,
				anl_base_thresh;
	float4		vac_scale_factor,
				anl_scale_factor;

	/* thresholds calculated from above constants */
	float4		vacthresh,
				anlthresh;


#if PG_VERSION_NUM >= 130000
	float4		vacinsthresh,
				vac_ins_base_thresh,
				instuples,
				vac_ins_scale_factor;
#endif 

	/* number of vacuum (resp. analyze) tuples at this time */
	float4		vactuples,
				anltuples;

	/* freeze parameters */
	int			freeze_max_age;
	int			multixact_freeze_max_age;
	TransactionId xidForceLimit;
	MultiXactId multiForceLimit;

	TransactionId recentXid;
	MultiXactId recentMulti;

	AssertArg(classForm != NULL);
	AssertArg(OidIsValid(relid));

	/*
	 * Determine vacuum/analyze equation parameters.  We have two possible
	 * sources: the passed reloptions (which could be a main table or a toast
	 * table), or the autovacuum GUC variables.
	 */

#if PG_VERSION_NUM >= 140000
	recentXid = ReadNextTransactionId();
#else
	recentXid = ReadNewTransactionId();
#endif
	recentMulti = ReadNextMultiXactId();


	/* -1 in autovac setting means use plain vacuum_scale_factor */
	vac_scale_factor = (relopts && relopts->vacuum_scale_factor >= 0)
		? relopts->vacuum_scale_factor
		: autovacuum_vac_scale;

	vac_base_thresh = (relopts && relopts->vacuum_threshold >= 0)
		? relopts->vacuum_threshold
		: autovacuum_vac_thresh;

#if PG_VERSION_NUM >= 130000
	vac_ins_scale_factor = (relopts && relopts->vacuum_ins_scale_factor >= 0)
		? relopts->vacuum_ins_scale_factor
		: autovacuum_vac_ins_scale;

	/* -1 is used to disable insert vacuums */
	vac_ins_base_thresh = (relopts && relopts->vacuum_ins_threshold >= -1)
		? relopts->vacuum_ins_threshold
		: autovacuum_vac_ins_thresh;
#endif 

	anl_scale_factor = (relopts && relopts->analyze_scale_factor >= 0)
		? relopts->analyze_scale_factor
		: autovacuum_anl_scale;

	anl_base_thresh = (relopts && relopts->analyze_threshold >= 0)
		? relopts->analyze_threshold
		: autovacuum_anl_thresh;

	freeze_max_age = (relopts && relopts->freeze_max_age >= 0)
		? Min(relopts->freeze_max_age, autovacuum_freeze_max_age)
		: autovacuum_freeze_max_age;

	multixact_freeze_max_age = (relopts && relopts->multixact_freeze_max_age >= 0)
		? Min(relopts->multixact_freeze_max_age, effective_multixact_freeze_max_age)
		: effective_multixact_freeze_max_age;

	av_enabled = (relopts ? relopts->enabled : true);

	/* Force vacuum if table is at risk of wraparound */
	xidForceLimit = recentXid - freeze_max_age;
	if (xidForceLimit < FirstNormalTransactionId)
		xidForceLimit -= FirstNormalTransactionId;
	force_vacuum = (TransactionIdIsNormal(classForm->relfrozenxid) &&
					TransactionIdPrecedes(classForm->relfrozenxid,
										  xidForceLimit));
	if (!force_vacuum)
	{
		multiForceLimit = recentMulti - multixact_freeze_max_age;
		if (multiForceLimit < FirstMultiXactId)
			multiForceLimit -= FirstMultiXactId;
		force_vacuum = MultiXactIdIsValid(classForm->relminmxid) &&
			MultiXactIdPrecedes(classForm->relminmxid, multiForceLimit);
	}
	*wraparound = force_vacuum;

	/* User disabled it in pg_class.reloptions?  (But ignore if at risk) */
	if (!av_enabled && !force_vacuum)
	{
		*doanalyze = false;
		*dovacuum = false;
		return;
	}

	/*
	 * If we found stats for the table, and autovacuum is currently enabled,
	 * make a threshold-based decision whether to vacuum and/or analyze.  If
	 * autovacuum is currently disabled, we must be here for anti-wraparound
	 * vacuuming only, so don't vacuum (or analyze) anything that's not being
	 * forced.
	 */
	if (PointerIsValid(tabentry) && AutoVacuumingActive())
	{
		reltuples = classForm->reltuples;
		vactuples = tabentry->n_dead_tuples;
#if PG_VSERION_NUM >= 130000
		instuples = tabentry->inserts_since_vacuum;
#endif
		anltuples = tabentry->changes_since_analyze;

		/* If the table hasn't yet been vacuumed, take reltuples as zero */
		if (reltuples < 0)
			reltuples = 0;

		vacthresh = (float4) vac_base_thresh + vac_scale_factor * reltuples;

#if PG_VERSION_NUM >= 130000
		vacinsthresh = (float4) vac_ins_base_thresh + vac_ins_scale_factor * reltuples;
#endif

		anlthresh = (float4) anl_base_thresh + anl_scale_factor * reltuples;


#if PG_VERSION_NUM >= 130000
		/*
		 * Note that we don't need to take special consideration for stat
		 * reset, because if that happens, the last vacuum and analyze counts
		 * will be reset too.
		 */
		if (vac_ins_base_thresh >= 0)
			elog(DEBUG3, "%s: vac: %.0f (threshold %.0f), ins: %.0f (threshold %.0f), anl: %.0f (threshold %.0f)",
				 NameStr(classForm->relname),
				 vactuples, vacthresh, instuples, vacinsthresh, anltuples, anlthresh);
		else
			elog(DEBUG3, "%s: vac: %.0f (threshold %.0f), ins: (disabled), anl: %.0f (threshold %.0f)",
				 NameStr(classForm->relname),
				 vactuples, vacthresh, anltuples, anlthresh);

		/* Determine if this table needs vacuum or analyze. */
		*dovacuum = force_vacuum || (vactuples > vacthresh) ||
			(vac_ins_base_thresh >= 0 && instuples > vacinsthresh);
		*doanalyze = (anltuples > anlthresh);
#else
				/*
		 * Note that we don't need to take special consideration for stat
		 * reset, because if that happens, the last vacuum and analyze counts
		 * will be reset too.
		 */
		elog(DEBUG3, "%s: vac: %.0f (threshold %.0f), ins: (disabled), anl: %.0f (threshold %.0f)",
				 NameStr(classForm->relname),
				 vactuples, vacthresh, anltuples, anlthresh);

		/* Determine if this table needs vacuum or analyze. */
		*dovacuum = force_vacuum || (vactuples > vacthresh);
		*doanalyze = (anltuples > anlthresh);
#endif
	}
	else
	{
		/*
		 * Skip a table not found in stat hash, unless we have to force vacuum
		 * for anti-wrap purposes.  If it's not acted upon, there's no need to
		 * vacuum it.
		 */
		*dovacuum = force_vacuum;
		*doanalyze = false;
	}

	/* ANALYZE refuses to work with pg_statistic */
	if (relid == StatisticRelationId)
		*doanalyze = false;
}

#if PG_VERSION_NUM >= 150000

#else
/*
 * get_pgstat_tabentry_relid
 *
 * Fetch the pgstat entry of a table, either local to a database or shared.
 */
static PgStat_StatTabEntry *
get_pgstat_tabentry_relid(Oid relid, bool isshared, PgStat_StatDBEntry *shared,
						  PgStat_StatDBEntry *dbentry)
{
	PgStat_StatTabEntry *tabentry = NULL;

	if (isshared)
	{
		if (PointerIsValid(shared))
			tabentry = hash_search(shared->tables, &relid,
								   HASH_FIND, NULL);
	}
	else if (PointerIsValid(dbentry))
		tabentry = hash_search(dbentry->tables, &relid,
							   HASH_FIND, NULL);

	return tabentry;
}

#endif 

/*
 * SQL function to check if tables need autovac or autoanalyze.
 */

Datum
autovacanalyze_check_internal(PG_FUNCTION_ARGS)
{
	Relation	classRel;
	HeapTuple	tuple;
#if PG_VERSION_NUM >= 120000
	TableScanDesc relScan;
#else
	HeapScanDesc relScan;
#endif
	List	   *table_oids = NIL;
	List	   *relations_meta = NIL;
	List	   *orphan_oids = NIL;
	TupleDesc	pg_class_desc;
	int			effective_multixact_freeze_max_age;
	vacanalyze_meta * tmp;
	vacanalyze_meta * curr;
	HeapTuple	resultTuple;
	Datum		result;
	Datum		values[3];
	bool		nulls[3];
	MemoryContext mctx;
	FuncCallContext *fctx;
#if PG_VERSION_NUM >= 150000
#else
	PgStat_StatDBEntry *shared;
	PgStat_StatDBEntry *dbentry;
#endif


	if (SRF_IS_FIRSTCALL())
	{

#if PG_VERSION_NUM >= 150000
#else

		/*
		* may be NULL if we couldn't find an entry (only happens if we are
		* forcing a vacuum for anti-wrap purposes).
		*/
		dbentry = pgstat_fetch_stat_dbentry(MyDatabaseId);

		/* The database hash where pgstat keeps shared relations */
		shared = pgstat_fetch_stat_dbentry(InvalidOid);
#endif

		fctx = SRF_FIRSTCALL_INIT();
		mctx = MemoryContextSwitchTo(fctx->multi_call_memory_ctx);

		effective_multixact_freeze_max_age = MultiXactMemberFreezeThreshold();

#if 	PG_VERSION_NUM >= 120000
		classRel = table_open(RelationRelationId, AccessShareLock);
#else
		classRel = heap_open(RelationRelationId, AccessShareLock);
#endif

		/* create a copy so we can use it after closing pg_class */
		pg_class_desc = CreateTupleDescCopy(RelationGetDescr(classRel));

		/*
		* Scan pg_class to determine which tables to vacuum.
		*
		* We do this in two passes: on the first one we collect the list of plain
		* relations and materialized views, and on the second one we collect
		* TOAST tables. The reason for doing the second pass is that during it we
		* want to use the main relation's pg_class.reloptions entry if the TOAST
		* table does not have any, and we cannot obtain it unless we know
		* beforehand what's the main table OID.
		*
		* We need to check TOAST tables separately because in cases with short,
		* wide tables there might be proportionally much more activity in the
		* TOAST table than in its parent.
		*/
#if 	PG_VERSION_NUM >= 120000
		relScan = table_beginscan_catalog(classRel, 0, NULL);
#else
		relScan = heap_beginscan_catalog(classRel, 0, NULL);
#endif

		/*
		* On the first pass, we collect main tables to vacuum, and also the main
		* table relid to TOAST relid mapping.
		*/
		while ((tuple = heap_getnext(relScan, ForwardScanDirection)) != NULL)
		{
			Form_pg_class classForm = (Form_pg_class) GETSTRUCT(tuple);
			PgStat_StatTabEntry *tabentry;
			AutoVacOpts *relopts;
			Oid			relid;
			bool		dovacuum;
			bool		doanalyze;
			bool		wraparound;

			if (classForm->relkind != RELKIND_RELATION &&
				classForm->relkind != RELKIND_MATVIEW)
				continue;

#if 		PG_VERSION_NUM >= 120000
			relid = classForm->oid;
#else
			relid = HeapTupleGetOid(tuple);
#endif
			/*
			* Check if it is a temp table (presumably, of some other backend's).
			* We cannot safely process other backends' temp tables.
			*/
			if (classForm->relpersistence == RELPERSISTENCE_TEMP)
			{
				/*
				* We just ignore it if the owning backend is still active and
				* using the temporary schema.  Also, for safety, ignore it if the
				* namespace doesn't exist or isn't a temp namespace after all.
				*/
				if (checkTempNamespaceStatus(classForm->relnamespace) == TEMP_NAMESPACE_IDLE)
				{
					/*
					* The table seems to be orphaned -- although it might be that
					* the owning backend has already deleted it and exited; our
					* pg_class scan snapshot is not necessarily up-to-date
					* anymore, so we could be looking at a committed-dead entry.
					* Remember it so we can try to delete it later.
					*/
					orphan_oids = lappend_oid(orphan_oids, relid);
				}
				continue;
			}

			/* Fetch reloptions and the pgstat entry for this table */
			relopts = extract_autovac_opts(tuple, pg_class_desc);
#if PG_VERSION_NUM >= 150000
			tabentry = pgstat_fetch_stat_tabentry_ext(classForm->relisshared,
													relid);
#else
			/* Fetch the pgstat entry for this table */
			tabentry = get_pgstat_tabentry_relid(relid, classForm->relisshared,
											 shared, dbentry);
#endif

			/* Check if it needs vacuum or analyze */
			relation_needs_vacanalyze(relid, relopts, classForm, tabentry,
									effective_multixact_freeze_max_age,
									&dovacuum, &doanalyze, &wraparound);

			/* Relations that need work are added to table_oids */
			if (dovacuum || doanalyze) {
				table_oids = lappend_oid(table_oids, relid);
				tmp = palloc0(sizeof(vacanalyze_meta));
				tmp->oid = relid;
				tmp->need_analyze = doanalyze;
				tmp->need_vacuum = dovacuum;
				relations_meta = lappend(relations_meta, tmp);
				fctx->max_calls++;
			}
		}

#if 	PG_VERSION_NUM >= 120000
		table_endscan(relScan);
		table_close(classRel, AccessShareLock);
#else
		heap_endscan(relScan);
		heap_close(classRel, AccessShareLock);
#endif

		fctx->user_fctx = relations_meta;
		fctx->call_cntr = 0;
		
		MemoryContextSwitchTo(mctx);
	}


	fctx = SRF_PERCALL_SETUP();

	/* Get the saved state */
	relations_meta = fctx->user_fctx;
	if (fctx->call_cntr < fctx->max_calls)
	{
		curr = lfirst(list_head(relations_meta));

		memset(nulls, 0, sizeof(nulls));

		values[0] = curr->oid;
		values[1] = curr->need_vacuum;
		values[2] = curr->need_analyze;

		/* Build and return the result tuple. */
		resultTuple = heap_form_tuple(autovacananlyze_check_tupdesc(), values, nulls);
		result = HeapTupleGetDatum(resultTuple);

		pfree(curr);
		fctx->user_fctx = list_delete_first(relations_meta);
		SRF_RETURN_NEXT(fctx, result);
	}
	else
		SRF_RETURN_DONE(fctx);
}
