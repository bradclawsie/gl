package GL::Org;
use v5.42;
use strictures 2;
use Crypt::Misc           qw( random_v4uuid );
use Time::Piece           ();
use Types::Common::String qw( NonEmptyStr );
use Types::UUID           qw( Uuid );
use GL::Attribute         qw( $DATE $ROLE_TEST $STATUS_ACTIVE );

use Moo;

our $VERSION   = '0.0.1';
our $AUTHORITY = 'cpan:bclawsie';

our $SCHEMA_VERSION = 0;

has name => (
  is       => 'ro',
  isa      => NonEmptyStr,
  required => true,
);

has owner => (
  is       => 'rw',
  isa      => Uuid,
  required => true,
  coerce   => 1,
  default  => Uuid->generator,
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

# for testing
sub random ($class, %args) {
  return $class->new(
    id     => $args{id}     // random_v4uuid,
    name   => $args{name}   // random_v4uuid,
    owner  => $args{owner}  // random_v4uuid,
    role   => $args{role}   // $ROLE_TEST,
    status => $args{status} // $STATUS_ACTIVE,
  );
}

with 'GL::Model::Base';

__END__
