# contrib/autovacanalyze_check/Makefile

MODULE_big = autovacanalyze_check
OBJS = \
	$(WIN32RES) \
	autovacanalyze_check.o

EXTENSION = autovacanalyze_check
DATA = autovacanalyze_check--1.0.sql 
PGFILEDESC = "autovacanalyze_check - checks if tables need vacuum or analyze"

REGRESS = autovacanalyze_check

ifdef USE_PGXS
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
else
subdir = contrib/autovacanalyze_check
top_builddir = ../..
include $(top_builddir)/src/Makefile.global
include $(top_srcdir)/contrib/contrib-global.mk
endif
