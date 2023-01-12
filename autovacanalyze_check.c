/*-------------------------------------------------------------------------
 *
 * pg_tm_aux.c
 *		Transfer manager auxilary functions
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
#include "access/tableam.h"
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
#include "postmaster/interrupt.h"
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

	tupdesc = CreateTemplateTupleDesc(maxattr);
	TupleDescInitEntry(tupdesc, 1, "relation_oid", OIDOID, -1, 0);
	TupleDescInitEntry(tupdesc, 2, "need_vacuum", BOOLOID, -1, 0);
	TupleDescInitEntry(tupdesc, 3, "need_analyze", BOOLOID, -1, 0);

	return BlessTupleDesc(tupdesc);
}


/*
 * SQL function to check if tables need autovac or autoanalyze.
 */

Datum
autovacanalyze_check_internal(PG_FUNCTION_ARGS)
{
	Relation	classRel;
	HeapTuple	tuple;
	TableScanDesc relScan;
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

	if (SRF_IS_FIRSTCALL())
	{
		fctx = SRF_FIRSTCALL_INIT();
		mctx = MemoryContextSwitchTo(fctx->multi_call_memory_ctx);

		effective_multixact_freeze_max_age = MultiXactMemberFreezeThreshold();

		classRel = table_open(RelationRelationId, AccessShareLock);

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
		relScan = table_beginscan_catalog(classRel, 0, NULL);

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

			relid = classForm->oid;

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
			tabentry = pgstat_fetch_stat_tabentry_ext(classForm->relisshared,
													relid);

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

		table_endscan(relScan);
		table_close(classRel, AccessShareLock);

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
