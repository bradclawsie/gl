package GL::Runtime::Development;
use v5.42;
use strictures 2;
use Carp            qw( croak );
use File::Basename  qw( dirname );
use Path::Tiny      qw( path );
use Types::Standard qw( ArrayRef Defined );

our $VERSION   = '0.0.1';
our $AUTHORITY = 'cpan:bclawsie';

use Moo;

has dbi => (
  is       => 'ro',
  isa      => ArrayRef [Defined],
  required => true,
  default  => sub {
    my $db_file = $ENV{DB_FILE} || croak 'DB_FILE not set';
    return [
      'dbi:SQLite:dbname=' . $db_file,
      q{}, q{},
      {
        RaiseError                       => 1,
        PrintError                       => 0,
        AutoCommit                       => 1,
        sqlite_unicode                   => 1,
        sqlite_allow_multiple_statements => 1,
      },
      ],
      ;
  },
);

sub BUILD ($self, $args) {
  my $db_file     = $ENV{DB_FILE}                  || croak 'DB_FILE not set';
  my $schema_file = $ENV{SCHEMA}                   || croak 'SCHEMA not set';
  my $schema      = path($schema_file)->slurp_utf8 || croak $!;
  if (-f $db_file) {
    my @tables = $self->dbh->tables;
    croak 'development db tables' if scalar @tables == 0;
  }
  else {
    my $db_dir = dirname($db_file);
    unless (-d $db_dir) {
      mkdir $db_dir || croak $!;
    }
    $self->dbh->do($schema);
  }
}

with 'GL::Runtime';

__END__
