package GL::Org;
use v5.42;
use strictures 2;
use Carp                  qw( croak );
use Crypt::Misc           qw( random_v4uuid );
use Readonly              ();
use Time::Piece           ();
use Type::Params          qw( signature_for );
use Types::Common::String qw( NonEmptyStr );
use Types::Standard       qw( ClassName HashRef InstanceOf Slurpy Value );
use Types::UUID           qw( Uuid );

use GL::Attribute qw( $DATE $ROLE_TEST $STATUS_ACTIVE );
use GL::User      ();

our $VERSION   = '0.0.1';
our $AUTHORITY = 'cpan:bclawsie';

Readonly::Scalar our $SCHEMA_VERSION => 0;

use Marlin
  -modifiers,
  -with => ['GL::Model'],

  'name!' => NonEmptyStr,

  'owner!' => InstanceOf ['GL::User'];

signature_for TO_JSON => (
  method     => true,
  positional => [],
);

sub TO_JSON ($self) {
  return {
    id    => $self->{id},
    name  => $self->{name},
    owner => $self->{owner},
    ctime => Time::Piece->gmtime($self->{ctime})->strftime($DATE),
    mtime => Time::Piece->gmtime($self->{mtime})->strftime($DATE),
  };
}

signature_for random => (
  method     => false,
  positional => [ ClassName, Slurpy [ HashRef [Value] ] ],
);

sub random ($class, $args) {
  my $id = $args->{id} // random_v4uuid;

  return $class->new(
    id             => $id,
    name           => $args->{name} // random_v4uuid,
    owner          => GL::User->random(org => $id),
    role           => $args->{role}           // $ROLE_TEST,
    schema_version => $args->{schema_version} // $SCHEMA_VERSION,
    status         => $args->{status}         // $STATUS_ACTIVE,
  );
}

__END__
