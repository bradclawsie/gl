set shell := ["bash", "-c"]

PWD := justfile_directory()
PERL5LIB_BASE := PWD / "local" / "lib" / "perl5"
PERL5LIB_LIB := PERL5LIB_BASE + ":" + PWD / "lib"
PERLCRITIC := "perlcritic" + " --profile " + PWD / ".perlcritic"
PERLIMPORTS := "perlimports -i --config-file=" + PWD / ".perlimports.toml"
PERLTIDY := 'perltidier'
PLACK_ENV := 'test'
YATH := 'yath'
DB_FILE := PWD / "db" / "dev.db"
SCHEMA := PWD / "sql" / "schema.sql"
LOCAL_BIN := PWD / "local" / "bin"
export PATH := LOCAL_BIN + ":" + env("PATH")
export PERL5LIB := PERL5LIB_LIB

default:
    @just --list

# Carton rules.

# Initialize carton.
carton:
    mkdir -p local/bin;
    curl -L https://cpanmin.us/ -o local/bin/cpanm
    @chmod +x local/bin/cpanm
    env -u PERL5LIB cpanm -l local -n -f Carton

# Install carton dependencies; follows "carton" rule.
deps:
    @carton install

# Update all carton dependencies.
update:
    @carton update

# App rules.

check:
    @for i in `find lib -name \*.pm`; do perl -c $i; done
    @for i in `find psgi -name \*.psgi`; do perl -c $i; done
    @for i in `find t -name \*.t`; do perl -c $i; done

critic:
    @find lib -name \*.pm -print0 | xargs -0 {{ PERLCRITIC }}
    @find psgi -name \*.psgi -print0 | xargs -0 {{ PERLCRITIC }}
    @find t -name \*.t -print0 | xargs -0 {{ PERLCRITIC }} --theme=tests

development-psgi:
    export \
      DB_FILE={{ DB_FILE }} \
      SCHEMA={{ SCHEMA }};\
      mkdir -p log && mkdir -p db && pushd psgi && plackup -E development app.psgi

test-psgi:
    export \
      SCHEMA={{ SCHEMA }};\
      mkdir -p log && pushd psgi && plackup -E test app.psgi

imports:
    @find lib -name \*.pm -print0 | xargs -0 {{ PERLIMPORTS }} 2>/dev/null
    @find psgi -name \*.psgi -print0 | xargs -0 {{ PERLIMPORTS }} 2>/dev/null
    @find t -name \*.t -print0 | xargs -0 {{ PERLIMPORTS }} 2>/dev/null

tidy:
    @find . -name \*.pm -print0 | xargs -0 {{ PERLTIDY }} 2>/dev/null
    @find . -name \*.psgi -print0 | xargs -0 {{ PERLTIDY }} 2>/dev/null
    @find . -name \*.t -print0 | xargs -0 {{ PERLTIDY }} 2>/dev/null
    @find -name \*bak -delete
    @find -name \*tdy -delete
    @find -name \*.ERR -delete

# Commands using "run".

run *CMD:
    @export \
      DB_FILE={{ DB_FILE }} \
      PLACK_ENV={{ PLACK_ENV }} \
      SCHEMA={{ SCHEMA }};\
      {{ CMD }}

repl: (run 'perl -de 0')

test: (run 'find t -name \*.t -print0 | xargs -0 ' + YATH)

# Run a single test; e.g. "just yath t/00-test.t".
yath TEST: (run YATH + " " + TEST)
