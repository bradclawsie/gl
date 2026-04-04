package GL::Crypt::IV;
use v5.42;
use strictures 2;
use Bytes::Random::Secure::Tiny ();
use Exporter                    qw( import );
use Readonly                    ();
use Type::Params                qw( signature_for );
use Type::Utils                 qw( as declare message where );
use Types::Standard             qw( Str );

use Type::Library -base, -declare => qw( IV );

our $VERSION   = '0.0.1';
our $AUTHORITY = 'cpan:bclawsie';

Readonly::Scalar our $HEX_LENGTH => 24;

declare IV, as Str, where { m/^[\da-f]{$HEX_LENGTH}$/x }, message { 'bad iv' };

signature_for random_iv => (
  method     => false,
  positional => [],
  returns    => IV,
);

sub random_iv {
  return Bytes::Random::Secure::Tiny->new->bytes_hex(int($HEX_LENGTH / 2));
}

our @EXPORT_OK   = (@EXPORT_OK, qw( random_iv ));
our %EXPORT_TAGS = (all => [ (@EXPORT_OK, qw( random_iv )) ]);

__END__
