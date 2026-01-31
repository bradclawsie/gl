package GL::Crypt::Key;
use v5.42;
use strictures 2;
use Bytes::Random::Secure::Tiny ();
use Exporter                    qw( import );
use Readonly                    ();

our $VERSION   = '0.01';
our $AUTHORITY = 'cpan:bclawsie';

Readonly::Scalar our $LENGTH => 32;

sub rand_key {
  my $rng = Bytes::Random::Secure::Tiny->new;
  return $rng->bytes_hex(int($LENGTH / 2));
}

our @EXPORT_OK   = qw( rand_key );
our %EXPORT_TAGS = (all => [qw( rand_key )]);

__END__
