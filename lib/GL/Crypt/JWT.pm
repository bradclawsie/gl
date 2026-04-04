package GL::Crypt::JWT;
use v5.42;
use strictures 2;
use Carp                   qw( croak );
use Crypt::JWT             qw( decode_jwt encode_jwt );
use Readonly               ();
use Type::Params           qw( signature_for );
use Types::Common::Numeric qw( PositiveInt );
use Types::Common::String  qw( NonEmptyStr );
use Types::Standard        qw( ClassName InstanceOf );
use Types::UUID            qw( Uuid );

our $VERSION   = '0.0.1';
our $AUTHORITY = 'cpan:bclawsie';

Readonly::Scalar our $TOKEN_TYPE => 'Bearer';

use Moo;
use namespace::clean;

has 'exp' => (
  is       => 'ro',
  isa      => PositiveInt->where('$_ > time'),
  required => true,
);

has [qw(id sub)] => (
  is       => 'ro',
  isa      => Uuid,
  required => true,
);

has 'iss' => (
  is       => 'ro',
  isa      => NonEmptyStr->where('$_ eq q{GrokLOC.com}'),
  required => true,
);

has 'nbf' => (
  is       => 'ro',
  isa      => PositiveInt->where('$_ < time'),
  required => true,
);

signature_for decode => (
  method     => false,
  positional => [ ClassName, NonEmptyStr, Uuid ],
  returns    => InstanceOf [__PACKAGE__],
);

sub decode ($class, $token, $token_key) {
  return $class->new(decode_jwt(token => $token, key => $token_key));
}

signature_for encode => (
  method     => true,
  positional => [Uuid],
  returns    => NonEmptyStr,
);

sub encode ($self, $token_key) {
  return encode_jwt(
    payload => {
      exp => $self->exp,
      id  => $self->id,
      iss => $self->iss,
      nbf => $self->nbf,
      sub => $self->sub,
    },
    alg => 'HS256',
    key => $token_key
  );
}

signature_for from_header => (
  method     => false,
  positional => [ ClassName, NonEmptyStr, Uuid ],
  returns    => InstanceOf [__PACKAGE__],
);

sub from_header ($class, $header, $token_key) {
  if ($header =~ m/^\Q$TOKEN_TYPE\E\s+(\S+)\s*$/x) {
    return $class->decode($1, $token_key);
  }
  croak 'bad header';
}

signature_for to_header => (
  method     => true,
  positional => [Uuid],
  returns    => NonEmptyStr,
);

sub to_header ($self, $token_key) {
  return $TOKEN_TYPE . q{ } . $self->encode($token_key);
}

__END__
