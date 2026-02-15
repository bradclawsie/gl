package GL::Runtime;
use v5.42;
use strictures 2;
use Carp                  qw( croak );
use Crypt::Misc           qw( random_v4uuid );
use DBIx::Connector       ();
use File::Spec            ();
use Log::Dispatch         ();
use Types::Standard       qw( ArrayRef CodeRef InstanceOf Str );
use Types::UUID           qw( Uuid );
use Types::Common::String qw( NonEmptyStr );

use GL::Attribute  qw( $ROLE_TEST );
use GL::Crypt::Key qw( random_key );
use GL::Org        ();
use GL::Type       qw( Role );
use GL::User       ();

our $VERSION   = '0.0.1';
our $AUTHORITY = 'cpan:bclawsie';

use Marlin::Role
  'api_version!' => {
  isa     => NonEmptyStr,
  default => 'v0',
  },

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

    # Create uuid() in sqlite.
    $dbh->sqlite_create_function('uuid', 0, sub { random_v4uuid }) || croak $!;

    return $conn;
  }
  },

  'dbh_pragmas!' => {
  isa     => ArrayRef [Str],
  default => sub {
    [
      'PRAGMA foreign_keys = OFF;',
      'PRAGMA journal_mode = WAL;',
      'PRAGMA synchronous = NORMAL',
    ]
  }
  },

  'default_role!' => {
  isa     => Role,
  default => $ROLE_TEST,
  },

  'get_key' => {
  isa     => CodeRef,
  lazy    => true,
  builder => sub ($self) {
    croak 'encryption_key_version not set yet'
      unless defined $self->encryption_key_version;
    my $encryption_keys = {
      $self->encryption_key_version => random_key,
      random_v4uuid()               => random_key,
      random_v4uuid()               => random_key,
    };
    return sub ($key_version) {
      return $encryption_keys->{$key_version} // croak 'bad key_version';
    };
  }
  },

  'encryption_key_version!' => {
  isa     => Uuid,
  default => Uuid->generator,
  },

  'logger' => {
  isa     => InstanceOf ['Log::Dispatch'],
  lazy    => true,
  builder => sub ($self) {
    return Log::Dispatch->new(outputs => $self->{log_outputs});
  },
  },

  'repository_base' => {
  isa     => Str,
  lazy    => true,
  builder => File::Spec->tmpdir,
  },

  'root!' => {
  isa     => InstanceOf ['GL::Org'],
  default => sub { GL::Org->random },
  },

  'signing_key' => {
  isa     => Uuid,
  lazy    => true,
  builder => Uuid->generator,
  },

  -requires => [qw( dbi log_outputs mode )];

__END__
