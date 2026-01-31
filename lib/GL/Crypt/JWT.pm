package GL::Crypt::JWT;
use v5.42;
use strictures 2;
use Carp                   qw( croak );
use Crypt::JWT             qw( decode_jwt encode_jwt );
use Readonly               ();
use Type::Params           qw( signature_for );
use Types::Common::Numeric qw( PositiveInt );
use Types::Common::String  qw( NonEmptyStr );
use Types::Standard        qw( ClassName );
use Types::UUID            qw( Uuid );

our $VERSION   = '0.01';
our $AUTHORITY = 'cpan:bclawsie';

Readonly::Scalar our $TOKEN_TYPE => 'Bearer';

use Marlin
  'exp!' => PositiveInt->where('$_ > time'),
  'id!'  => {isa => Uuid, coerce => 1},
  'iss!' => NonEmptyStr->where('$_ eq q{GrokLOC.com}'),
  'nbf!' => PositiveInt->where('$_ < time'),
  'sub!' => {isa => Uuid, coerce => 1};

signature_for decode => (
  method     => false,
  positional => [ ClassName, NonEmptyStr, Uuid ],
);

sub decode ($class, $token, $signing_key) {
  return $class->new(decode_jwt(token => $token, key => $signing_key));
}

signature_for encode => (
  method     => true,
  positional => [Uuid],
);

sub encode ($self, $signing_key) {
  return encode_jwt(
    payload => {
      exp => $self->exp,
      id  => $self->id,
      iss => $self->iss,
      nbf => $self->nbf,
      sub => $self->sub,
    },
    alg => 'HS256',
    key => $signing_key
  );
}

signature_for from_header => (
  method     => false,
  positional => [ ClassName, NonEmptyStr, Uuid ],
);

sub from_header ($class, $header, $signing_key) {
  if ($header =~ m/^$TOKEN_TYPE\s+(\S+)\s*$/x) {
    return $class->decode($1, $signing_key);
  }
  croak 'bad header';
}

signature_for to_header => (
  method     => true,
  positional => [Uuid],
);

sub to_header ($self, $signing_key) {
  return $TOKEN_TYPE . q{ } . $self->encode($signing_key);
}

__END__
