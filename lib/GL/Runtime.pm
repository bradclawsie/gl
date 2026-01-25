package GL::Runtime;
use v5.42;
use strictures 2;
use Carp            qw( croak );
use Crypt::Misc     qw( random_v4uuid );
use DBI             ();
use File::Spec      ();
use Types::Standard qw( ArrayRef CodeRef InstanceOf Str );
use Types::UUID     qw( Uuid );

use GL::Attribute  qw( $ROLE_TEST );
use GL::Crypt::Key qw( rand_key );
use GL::Type       qw( Role );

our $VERSION   = '0.0.1';
our $AUTHORITY = 'cpan:bclawsie';

use Moo::Role;

# Defaults here are for test/development environments.

requires 'dbi';

has api_version => (
  is       => 'ro',
  required => true,
  default  => sub { 'v0' },
);

has dbh => (
  is       => 'ro',
  isa      => InstanceOf ['DBI::db'],
  required => true,
  lazy     => true,
  default  => sub ($self) {
    my $dbh = DBI->connect(@{$self->dbi}) || croak $DBI::errstr;
    for my $pragma (@{$self->dbh_pragmas}) {
      $dbh->do($pragma) || croak $!;
    }
    return $dbh;
  },
);

has dbh_pragmas => (
  is       => 'ro',
  isa      => ArrayRef [Str],
  required => true,
  default  => sub {
    [
      'PRAGMA foreign_keys = ON;',
      'PRAGMA journal_mode = WAL;',
      'PRAGMA synchronous = NORMAL',
    ]
  },
);

has default_role => (
  is       => 'ro',
  isa      => Role,
  required => true,
  default  => sub { $ROLE_TEST },
);

has get_key => (
  is       => 'ro',
  isa      => CodeRef,
  lazy     => true,
  required => true,
  builder  => sub ($self) {
    my $encryption_keys = {
      $self->encryption_key_version => rand_key,
      random_v4uuid()               => rand_key,
      random_v4uuid()               => rand_key,
    };
    my $get_key = sub ($key_version) {
      return $encryption_keys->{$key_version} // croak 'bad key_version';
    };
    return $get_key;
  },
);

has [qw(encryption_key_version signing_key)] => (
  is       => 'ro',
  isa      => Uuid,
  required => true,
  default  => Uuid->generator,
);

has reqpository_base => (
  is       => 'ro',
  required => true,
  default  => sub { File::Spec->tmpdir },
);

__END__
