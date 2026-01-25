package GL::Runtime::Test;
use v5.42;
use strictures 2;
use Carp            qw( croak );
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
    return [
      'dbi:SQLite:dbname=:memory:',
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

  # build :memory: db
  my $schema_file = $ENV{SCHEMA}                   || croak 'SCHEMA not set';
  my $schema      = path($schema_file)->slurp_utf8 || croak $!;
  $self->dbh->do($schema);
}

with 'GL::Runtime';

__END__
