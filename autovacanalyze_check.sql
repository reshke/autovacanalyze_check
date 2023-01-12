CREATE OR REPLACE FUNCTION
autovacanalyze_check_internal(VOID)
RETURNS TABLE (relation_oid OID, need_vacuum BOOLEAN, need_analyze BOOLEAN)
AS 'MODULE_PATHNAME', 'autovacanalyze_check_internal'
LANGUAGE C STRICT;


CREATE OR REPLACE FUNCTION
autovacanalyze_check()
RETURNS TABLE (relation TEXT, need_vacuum BOOLEAN, need_analyze BOOLEAN)
AS $$
    SELECT 
        (SELECT relname FROM pg_class where oid = ai.reloid), 
        ai.need_vacuum, 
        ai.need_analyze 
    FROM autovacanalyze_check_internal() ai;
$$
LANGUAGE C SQL;