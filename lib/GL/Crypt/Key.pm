package GL::Crypt::Key;
use v5.42;
use strictures 2;
use Bytes::Random::Secure::Tiny ();
use Readonly                    ();
use Type::Params                qw( signature_for );
use Type::Utils                 qw( as declare message where );
use Types::Standard             qw( Str );

use Type::Library -base, -declare => qw( Key );

our $VERSION   = '0.0.1';
our $AUTHORITY = 'cpan:bclawsie';

Readonly::Scalar our $HEX_LENGTH => 32;

declare Key, as Str, where { m/^[\da-f]{$HEX_LENGTH}$/x },
  message { 'bad key' };

signature_for random_key => (
  method     => false,
  positional => [],
  returns    => Key,
);

sub random_key {
  return Bytes::Random::Secure::Tiny->new->bytes_hex(int($HEX_LENGTH / 2));
}

our @EXPORT_OK   = (@EXPORT_OK, qw( random_key ));
our %EXPORT_TAGS = (all => [ (@EXPORT_OK, qw( random_key )) ]);

__END__
