package GL::Org;
use v5.42;
use strictures 2;
use Crypt::Misc           qw( random_v4uuid );
use Readonly              ();
use Time::Piece           ();
use Type::Params          qw( signature_for );
use Types::Common::String qw( NonEmptyStr );
use Types::Standard       qw( ClassName HashRef Slurpy Value );
use Types::UUID           qw( Uuid );

use GL::Attribute qw( $DATE $ROLE_TEST $STATUS_ACTIVE );

our $VERSION   = '0.0.1';
our $AUTHORITY = 'cpan:bclawsie';

Readonly::Scalar our $SCHEMA_VERSION => 0;

use Marlin
  -modifiers,
  -with => ['GL::Model'],

  'name!' => NonEmptyStr,

  'owner!' => Uuid;

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
  return $class->new(
    id             => $args->{id}             // random_v4uuid,
    name           => $args->{name}           // random_v4uuid,
    owner          => $args->{owner}          // random_v4uuid,
    role           => $args->{role}           // $ROLE_TEST,
    schema_version => $args->{schema_version} // $SCHEMA_VERSION,
    status         => $args->{status}         // $STATUS_ACTIVE,
  );
}

__END__
