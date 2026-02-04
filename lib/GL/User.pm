package GL::User;
use v5.42;
use strictures 2;
use Crypt::Digest::SHA256 qw( sha256_hex );
use Crypt::Misc           qw( random_v4uuid );
use Crypt::PK::Ed25519    ();
use Time::Piece           ();
use Type::Params          qw( signature_for );
use Types::Common::String qw( NonEmptyStr );
use Types::Standard       qw( ClassName HashRef Slurpy Value );
use Types::UUID           qw( Uuid );

use GL::Attribute       qw( $DATE $ROLE_TEST $STATUS_ACTIVE );
use GL::Crypt::Password qw( rand_password );

our $VERSION   = '0.0.1';
our $AUTHORITY = 'cpan:bclawsie';

use Marlin
  -modifiers,
  -with => ['GL::Model'],

  'display_name==!' => {
  isa     => NonEmptyStr,
  trigger => sub ($self, @args) {
    return unless scalar(@args) && defined($args[0]);
    $self->{display_name_digest} = sha256_hex($args[0]);
  },
  },

  'display_name_digest' => NonEmptyStr,

  # If no ed25519_public was present at construction, then
  # caller needs public and private keys set. Private key
  # should be made available to caller then object destroyed.
  'ed25519_private.' => {
  isa     => NonEmptyStr,
  builder => sub ($self) {
    unless (defined $self->{ed25519_public}) {
      my $pk = Crypt::PK::Ed25519->new->generate_key;
      $self->{ed25519_private} = $pk->export_key_pem('private');
      my $public_key = $pk->export_key_pem('public');
      $self->{ed25519_public}        = $public_key;
      $self->{ed25519_public_digest} = sha256_hex($public_key);
    }
  },
  },

  'ed25519_public==' => {
  isa     => NonEmptyStr,
  trigger => sub ($self, @args) {
    return unless scalar(@args) && defined($args[0]);
    $self->{ed25519_public_digest} = sha256_hex($args[0]);
    $self->{ed25519_private}       = undef;
  },
  },

  'ed25519_public_digest' => NonEmptyStr,

  'email!' => {
  isa     => NonEmptyStr,
  trigger => sub ($self, @args) {
    return unless scalar(@args) && defined($args[0]);
    $self->{email_digest} = sha256_hex($args[0]);
  },
  },

  'email_digest' => NonEmptyStr,

  # Required before any db operation.
  'key_version==' => {isa => Uuid, coerce => 1},

  'org!' => {isa => Uuid, coerce => 1},

  'password==!' => {
  isa     => NonEmptyStr->where('$_ =~ m/\$argon2/'),
  default => rand_password,
  };

signature_for TO_JSON => (
  method     => true,
  positional => [],
);

sub TO_JSON ($self) {
  return {
    id             => $self->{id},
    name           => $self->{display_name},
    email          => $self->{email},
    org            => $self->{org},
    ed25519_public => $self->{ed25519_public},
    ctime          => Time::Piece->gmtime($self->{ctime})->strftime($DATE),
    mtime          => Time::Piece->gmtime($self->{mtime})->strftime($DATE),
  };
}

signature_for random => (
  method     => false,
  positional => [ ClassName, Slurpy [ HashRef [Value] ] ],
);

sub random ($class, $args) {

  # Random User just gets new ed25519 key pair by default.
  return $class->new(
    display_name => $args->{display_name} // random_v4uuid,
    email        => $args->{email}        // random_v4uuid,
    id           => $args->{id}           // random_v4uuid,
    org          => $args->{org}          // random_v4uuid,
    password     => $args->{password}     // rand_password,
    role         => $args->{role}         // $ROLE_TEST,
    status       => $args->{status}       // $STATUS_ACTIVE,
  );
}

__END__
