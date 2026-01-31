package GL::Runtime;
use v5.42;
use strictures 2;
use Carp            qw( croak );
use Crypt::Misc     qw( random_v4uuid );
use DBIx::Connector ();
use File::Spec      ();
use Types::Standard qw( ArrayRef CodeRef InstanceOf Str );
use Types::UUID     qw( Uuid );

use GL::Attribute  qw( $ROLE_TEST );
use GL::Crypt::Key qw( rand_key );
use GL::Type       qw( Role );

our $VERSION   = '0.0.1';
our $AUTHORITY = 'cpan:bclawsie';

use Marlin::Role
  'api_version!' => {isa => Str, default => 'v0'},

  'db' => {
  isa     => InstanceOf ['DBIx::Connector'],
  lazy    => true,
  default => sub ($self) {
    my $conn = DBIx::Connector->new(@{$self->dbi});
    $conn->mode('ping');
    my $dbh = $conn->dbh;
    for my $pragma (@{$self->dbh_pragmas}) {
      $dbh->do($pragma) || croak $!;
    }
    return $conn;
  },
  },

  'dbh_pragmas!' => {
  isa     => ArrayRef [Str],
  default => sub {
    [
      'PRAGMA foreign_keys = ON;',
      'PRAGMA journal_mode = WAL;',
      'PRAGMA synchronous = NORMAL',
    ]
  },
  },

  'default_role!' => {isa => Role, default => $ROLE_TEST},

  'get_key' => {
  isa     => CodeRef,
  lazy    => true,
  builder => sub ($self) {
    my $encryption_keys = {
      $self->encryption_key_version => rand_key,
      random_v4uuid()               => rand_key,
      random_v4uuid()               => rand_key,
    };
    return sub ($key_version) {
      return $encryption_keys->{$key_version} // croak 'bad key_version';
    };
  }
  },

  'encryption_key_version!' => {isa => Uuid, default => Uuid->generator},

  'repository_base' =>
  {isa => Str, lazy => true, builder => File::Spec->tmpdir},

  'signing_key' => {isa => Uuid, lazy => true, builder => Uuid->generator},

  -requires => [qw( dbi )];

__END__
