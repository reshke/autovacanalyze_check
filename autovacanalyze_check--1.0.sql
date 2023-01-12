CREATE OR REPLACE FUNCTION
autovacanalyze_check_internal()
RETURNS TABLE (relation_oid OID, need_vacuum BOOLEAN, need_analyze BOOLEAN)
AS 'MODULE_PATHNAME', 'autovacanalyze_check_internal'
LANGUAGE C STRICT;


CREATE OR REPLACE VIEW
autovacanalyze_check
AS
    SELECT 
        (SELECT relname FROM pg_class where oid = ai.relation_oid) AS relation, 
        ai.need_vacuum AS relation_need_vacuum, 
        ai.need_analyze AS relation_need_analyze
    FROM autovacanalyze_check_internal() ai;