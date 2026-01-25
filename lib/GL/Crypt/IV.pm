package GL::Crypt::IV;
use v5.42;
use strictures 2;
use Bytes::Random::Secure::Tiny ();
use Exporter                    qw( import );

our $VERSION   = '0.01';
our $AUTHORITY = 'cpan:bclawsie';

our $LENGTH = 16;

sub rand_iv {
  my $rng = Bytes::Random::Secure::Tiny->new;
  return $rng->bytes_hex(int($LENGTH / 2));
}

our @EXPORT_OK   = qw( rand_iv );
our %EXPORT_TAGS = (all => [qw( rand_iv )]);

__END__
