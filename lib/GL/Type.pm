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
