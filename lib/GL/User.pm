package GL::User;
use v5.42;
use strictures 2;
use Carp                  qw( croak );
use Crypt::Digest::SHA256 qw( sha256_hex );
use Crypt::Misc           qw( random_v4uuid );
use Crypt::PK::Ed25519    ();
use Time::Piece           ();
use Types::Common::String qw( NonEmptyStr );
use Types::Standard       qw( Maybe );
use Types::UUID           qw( Uuid );
use GL::Crypt::Password   qw( rand_password );
use GL::Attribute         qw( $DATE $ROLE_TEST $STATUS_ACTIVE );

use Moo;

our $VERSION   = '0.0.1';
our $AUTHORITY = 'cpan:bclawsie';

our $SCHEMA_VERSION = 0;

has display_name => (
  is       => 'rw',
  isa      => NonEmptyStr,
  required => true,
  trigger  => sub ($self, $v) {
    $self->_set_display_name_digest(sha256_hex($v));
  },
);

has display_name_digest => (
  is       => 'ro',
  isa      => NonEmptyStr,
  required => false,
  writer   => '_set_display_name_digest',
);

# Will be set only if caller has not provided ed25519_public.
# Return this to caller scope and then destroy object promptly.
has ed25519_private => (
  is       => 'ro',
  isa      => Maybe [NonEmptyStr],
  required => false,
  trigger  => sub ($self, $v) {
    try {
      my $k = Crypt::PK::Ed25519->new(\$v);
      croak 'not private key' unless $k->is_private;
    }
    catch ($e) {
      croak "bad ed25519 private key: $e";
    }
  },
);

has ed25519_public => (
  is       => 'rw',
  isa      => NonEmptyStr,
  required => true,
  trigger  => sub ($self, $v) {
    try {
      my $k = Crypt::PK::Ed25519->new(\$v);
      croak 'not public key' if $k->is_private;
    }
    catch ($e) {
      croak "bad ed25519 public key: $e";
    }
    $self->_set_ed25519_public_digest(sha256_hex($v));
  },
);

has ed25519_public_digest => (
  is       => 'ro',
  isa      => NonEmptyStr,
  required => false,
  writer   => '_set_ed25519_public_digest',
);

has email => (
  is       => 'ro',
  isa      => NonEmptyStr,
  required => true,
  trigger  => sub ($self, $v) {
    $self->_set_email_digest(sha256_hex($v));
  },
);

has email_digest => (
  is       => 'ro',
  isa      => NonEmptyStr,
  required => false,
  writer   => '_set_email_digest',
);

has key_version => (
  is       => 'rw',
  isa      => Uuid,
  required => false,    # only needed at db insert/update
  coerce   => 1,
  default  => sub { '00000000-0000-0000-0000-000000000000' },
);

has org => (
  is       => 'ro',
  isa      => Uuid,
  required => true,
  coerce   => 1,
  default  => sub { '00000000-0000-0000-0000-000000000000' },
);

has password => (
  is       => 'rw',
  isa      => NonEmptyStr->where('$_ =~ m/\$argon2/'),
  required => true,
  default  => sub { rand_password },
);

around BUILDARGS => sub {
  my ($orig, $class, @args) = @_;
  my $params = $class->$orig(@args);

  # If no ed25519_public was provided, then caller needs
  # a new key generated.
  unless (defined $params->{ed25519_public}) {
    my $pk = Crypt::PK::Ed25519->new->generate_key;
    $params->{ed25519_private} = $pk->export_key_pem('private');
    $params->{ed25519_public}  = $pk->export_key_pem('public');
  }

  return $params;
};

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

# for testing
sub random ($class, %args) {
  return $class->new(
    display_name   => $args{display_name}   // random_v4uuid,
    ed25519_public => $args{ed25519_public} // undef,
    email          => $args{email}          // random_v4uuid,
    id             => $args{id}             // random_v4uuid,
    org            => $args{org}            // random_v4uuid,
    password       => $args{password}       // rand_password,
    role           => $args{role}           // $ROLE_TEST,
    status         => $args{status}         // $STATUS_ACTIVE,
  );
}

with 'GL::Model::Base';

__END__
