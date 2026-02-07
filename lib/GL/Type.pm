package GL::Type;
use v5.42;
use strictures 2;
use Type::Library -base;
use Type::Tiny;

use GL::Attribute qw(
  $ROLE_ADMIN
  $ROLE_NORMAL
  $ROLE_TEST
  $STATUS_ACTIVE
  $STATUS_INACTIVE
  $STATUS_UNCONFIRMED
);
use GL::Crypt::IV  ();
use GL::Crypt::Key ();

our $VERSION   = '0.0.1';
our $AUTHORITY = 'cpan:bclawsie';

my $db = 'Type::Tiny'->new(
  name       => 'DB',
  constraint => sub { $_ isa DBIx::Connector },
  message    => sub { 'bad db' },
);
__PACKAGE__->meta->add_type($db);

my $digest = 'Type::Tiny'->new(
  name       => 'Digest',
  constraint => sub { m/^[\da-fA-F]{64}$/x },
  message    => sub { 'bad digest' },
);
__PACKAGE__->meta->add_type($digest);

my $ed25519 = 'Type::Tiny'->new(
  name       => 'Ed25519',
  constraint => sub {
    m{
      ^-----BEGIN\s(PUBLIC|PRIVATE)\sKEY-----\s+
      ([[:alpha:]\d+/=\s]+)
      -----END\s\1\sKEY-----\s*$
      }mx;
  },
  message => sub { 'bad ed25519' },
);
__PACKAGE__->meta->add_type($ed25519);

my $iv = 'Type::Tiny'->new(
  name       => 'IV',
  constraint => sub { m/^[\da-f]{$GL::Crypt::IV::LENGTH}$/x },
  message    => sub { 'bad iv' },
);
__PACKAGE__->meta->add_type($iv);

my $key = 'Type::Tiny'->new(
  name       => 'Key',
  constraint => sub { m/^[\da-f]{$GL::Crypt::Key::LENGTH}$/x },
  message    => sub { 'bad key' },
);
__PACKAGE__->meta->add_type($key);

my $role = 'Type::Tiny'->new(
  name       => 'Role',
  constraint =>
    sub { $_ == $ROLE_NORMAL || $_ == $ROLE_ADMIN || $_ == $ROLE_TEST },
  message => sub { 'bad role' },
);
__PACKAGE__->meta->add_type($role);

my $status = 'Type::Tiny'->new(
  name       => 'Status',
  constraint => sub {
    $_ == $STATUS_UNCONFIRMED || $_ == $STATUS_ACTIVE || $_ == $STATUS_INACTIVE;
  },
  message => sub { 'bad status' },
);
__PACKAGE__->meta->add_type($status);

__PACKAGE__->meta->make_immutable;

__END__
