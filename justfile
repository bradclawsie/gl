set shell := ["bash", "-c"]

PWD           := justfile_directory()

PERL5LIB_BASE := PWD / "local" / "lib" / "perl5"
PERL5LIB_LIB  := PERL5LIB_BASE + ":" + PWD / "lib"

PERLCRITIC    := "perlcritic" + " --profile " + PWD / ".perlcritic"
PERLIMPORTS   := "perlimports -i --config-file=" + PWD / ".perlimports.toml"
PERLTIDY      := 'perltidier'
PLACK_ENV     := 'test'
YATH          := 'yath'

SCHEMA        := PWD / "sql" / "schema.sql"

LOCAL_BIN     := PWD / "local" / "bin"
export PATH   := LOCAL_BIN + ":" + env("PATH")

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
    @export PERL5LIB={{ PERL5LIB_BASE }};\
      carton install

# Update all carton dependencies.
update:
    @export PERL5LIB={{ PERL5LIB_BASE }};\
      carton update

# App rules.

check:
    @export PERL5LIB={{ PERL5LIB_LIB }};\
      for i in `find lib -name \*.pm`; do perl -c $i; done
    @export PERL5LIB={{ PERL5LIB_LIB }};\
      for i in `find t -name \*.t`; do perl -c $i; done

critic:
    @export PERL5LIB={{ PERL5LIB_LIB }};\
      find lib -name \*.pm -print0 | xargs -0 {{ PERLCRITIC }}
    @export PERL5LIB={{ PERL5LIB_LIB }};\
      find t -name \*.t -print0 | xargs -0 {{ PERLCRITIC }} --theme=tests

daemon:
    @export \
      PERL5LIB={{ PERL5LIB_LIB }} \
      SCHEMA={{ SCHEMA }};\
      mkdir -p log && mkdir -p db && plackup -E development app.psgi

imports:
    @export PERL5LIB={{ PERL5LIB_LIB }};\
      find lib -name \*.pm -print0 | xargs -0 {{ PERLIMPORTS }} 2>/dev/null
    @export PERL5LIB={{ PERL5LIB_LIB }};\
      find t -name \*.t -print0 | xargs -0 {{ PERLIMPORTS }} 2>/dev/null

repl:
    @export PERL5LIB={{ PERL5LIB_LIB }};\
      perl -de 0

run *CMD:
    @export PERL5LIB={{ PERL5LIB_LIB }};\
      {{ CMD }}

test:
    @export \
      PERL5LIB={{ PERL5LIB_LIB }} \
      PLACK_ENV={{ PLACK_ENV }} \
      SCHEMA={{ SCHEMA }};\
      find t -name \*.t -print0 | xargs -0 {{ YATH }}

tidy:
    @export PERL5LIB={{ PERL5LIB_BASE }};\
      find . -name \*.pm -print0 | xargs -0 {{ PERLTIDY }} 2>/dev/null
    @export PERL5LIB={{ PERL5LIB_BASE }};\
      find . -name \*.t -print0 | xargs -0 {{ PERLTIDY }} 2>/dev/null
    @find -name \*bak -delete
    @find -name \*tdy -delete
    @find -name \*.ERR -delete

# Run a single test; e.g. "just yath t/00-test.t".
yath TEST:
    @export \
      PERL5LIB={{ PERL5LIB_LIB }} \
      PLACK_ENV={{ PLACK_ENV }} \
      SCHEMA={{ SCHEMA }};\
      {{ YATH }} {{ TEST }}
