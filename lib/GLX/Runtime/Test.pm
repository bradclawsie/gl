package GLX::Runtime::Test;
use v5.42;
use strictures 2;
use Carp                 qw( croak );
use Log::Dispatch::Array ();
use Path::Tiny           qw( path );
use Types::Standard      qw( ArrayRef Defined Object );

use GLX::LogLine;

our $VERSION   = '0.0.1';
our $AUTHORITY = 'cpan:bclawsie';

use Moo;
use namespace::clean;

has 'dbi' => (
  is      => 'ro',
  isa     => ArrayRef [Defined],
  default => sub {
    [
      'dbi:SQLite:dbname=:memory:',
      q{}, q{},
      {
        RaiseError                       => 1,
        PrintError                       => 0,
        AutoCommit                       => 1,
        sqlite_unicode                   => 1,
        sqlite_allow_multiple_statements => 1,
      },
    ];
  },
);

has 'dispatcher' => (
  is      => 'ro',
  isa     => Object,
  default => sub {
    Log::Dispatch::Array->new(
      name      => 'test',
      min_level => 'debug',
      callbacks => GLX::LogLine->logdispatch_callback,
    );
  },
);

sub BUILD ($self, $args) {

  $self->_set_mode('test');

  # Build :memory: db.
  my $schema_file = $ENV{SCHEMA}                   || croak 'SCHEMA not set';
  my $schema      = path($schema_file)->slurp_utf8 || croak $!;
  $self->db->txn(fixup => sub ($dbh) { $dbh->do($schema) });

  # Finish setting up root.
  $self->root->owner->{key_version} = $self->encryption_key_version;
}

with 'GLX::Runtime';

__END__
