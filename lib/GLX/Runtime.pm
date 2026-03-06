package GLX::Runtime;
use v5.42;
use strictures 2;
use Carp                  qw( croak );
use Crypt::Mac::HMAC      qw( hmac_hex );
use Crypt::Misc           qw( random_v4uuid );
use DBIx::Connector       ();
use File::Spec            ();
use Log::Dispatch         ();
use Time::Piece           qw( localtime );
use Types::Common::String qw( NonEmptyStr );
use Types::Standard       qw( ArrayRef CodeRef InstanceOf Str );
use Types::UUID           qw( Uuid );

use GL::Attribute  qw( $ROLE_TEST );
use GL::Crypt::Key qw( random_key );
use GL::Org        ();
use GL::Type       qw( DB Org Role );
use GL::User       ();

our $VERSION   = '0.0.1';
our $AUTHORITY = 'cpan:bclawsie';

use Moo::Role;
use namespace::clean;

has 'api_version' => (
  is       => 'ro',
  isa      => NonEmptyStr,
  required => true,
);

has 'db' => (
  is      => 'ro',
  isa     => DB,
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
  },
);

has 'dbh_pragmas' => (
  is      => 'ro',
  isa     => ArrayRef [Str],
  default => sub {
    [
      'PRAGMA foreign_keys = OFF;',
      'PRAGMA journal_mode = WAL;',
      'PRAGMA synchronous = NORMAL',
    ]
  },
);

has 'default_role' => (
  is      => 'ro',
  isa     => Role,
  default => $ROLE_TEST,
);

has 'encryption_key_version' => (
  is      => 'ro',
  isa     => Uuid,
  default => Uuid->generator,
);

has 'get_key' => (
  is      => 'ro',
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
  },
);

has 'hmac' => (
  is      => 'ro',
  isa     => CodeRef,
  lazy    => true,
  builder => sub ($self) {
    my $key = random_v4uuid;
    return sub ($data) {
      return hmac_hex('SHA256', $key, $data);
    };
  },
);

has 'log' => (
  is      => 'ro',
  isa     => InstanceOf ['Log::Dispatch'],
  lazy    => true,
  builder => sub ($self) {
    my $ld = Log::Dispatch->new;
    $ld->add($self->dispatcher);
    return $ld;
  },
);

has 'repository_base' => (
  is      => 'ro',
  isa     => NonEmptyStr,
  lazy    => true,
  default => File::Spec->tmpdir,
);

has 'root' => (
  is      => 'ro',
  isa     => Org,
  default => sub { GL::Org->random },
);

has 'started_at' => (
  is      => 'ro',
  isa     => InstanceOf ['Time::Piece'],
  default => sub { localtime },
);

has 'token_key' => (
  is      => 'ro',
  isa     => Uuid,
  default => Uuid->generator,
);

requires 'dbi';
requires 'dispatcher';
requires 'mode';

__END__
