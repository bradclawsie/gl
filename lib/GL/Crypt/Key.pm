package GL::Crypt::Key;
use v5.42;
use strictures 2;
use Bytes::Random::Secure::Tiny ();
use Exporter                    qw( import );
use Readonly                    ();

our $VERSION   = '0.0.1';
our $AUTHORITY = 'cpan:bclawsie';

Readonly::Scalar our $HEX_LENGTH => 32;

sub random_key {
  return Bytes::Random::Secure::Tiny->new->bytes_hex(int($HEX_LENGTH / 2));
}

our @EXPORT_OK   = qw( random_key );
our %EXPORT_TAGS = (all => [qw( random_key )]);

__END__
