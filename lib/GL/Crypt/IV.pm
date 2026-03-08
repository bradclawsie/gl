package GL::Crypt::IV;
use v5.42;
use strictures 2;
use Bytes::Random::Secure::Tiny ();
use Exporter                    qw( import );
use Readonly                    ();

our $VERSION   = '0.0.1';
our $AUTHORITY = 'cpan:bclawsie';

Readonly::Scalar our $HEX_LENGTH => 24;

sub random_iv {
  my $rng = Bytes::Random::Secure::Tiny->new;
  return $rng->bytes_hex(int($HEX_LENGTH / 2));
}

our @EXPORT_OK   = qw( random_iv );
our %EXPORT_TAGS = (all => [qw( random_iv )]);

__END__
