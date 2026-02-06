package GL::Crypt::Password;
use v5.42;
use strictures 2;
use Bytes::Random::Secure::Tiny ();
use Crypt::Argon2               qw( argon2_verify argon2id_pass );
use Exporter                    qw( import );
use Readonly                    ();

our $VERSION   = '0.0.1';
our $AUTHORITY = 'cpan:bclawsie';

Readonly::Scalar our $SALT_LENGTH => 16;

sub text_to_password ($text) {
  my $rng  = Bytes::Random::Secure::Tiny->new;
  my $salt = $rng->bytes_hex(int($SALT_LENGTH / 2));
  return argon2id_pass($text, $salt, 1, '32M', 1, 16);
}

sub verify_password ($password, $text) {
  return argon2_verify($password, $text);
}

sub random_password {
  my $rng = Bytes::Random::Secure::Tiny->new;
  return text_to_password($rng->bytes_hex(8));
}

our @EXPORT_OK = qw( text_to_password verify_password random_password );
our %EXPORT_TAGS =
  (all => [qw( text_to_password verify_password random_password)]);

__END__

