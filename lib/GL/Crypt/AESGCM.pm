package GL::Crypt::AESGCM;
use v5.42;
use strictures 2;
use Carp                  qw( croak );
use Exporter              qw( import );
use Crypt::AuthEnc::GCM   ();
use Type::Params          qw( signature_for );
use Types::Common::String qw( NonEmptyStr );

use GL::Type qw( IV Key );

our $VERSION   = '0.01';
our $AUTHORITY = 'cpan:bclawsie';

our $TAG_LENGTH = 32;

signature_for encrypt => (
  method     => false,
  positional => [ NonEmptyStr, Key, IV ],
  returns    => NonEmptyStr,
);

sub encrypt ($text, $key, $iv) {
  my $ae  = Crypt::AuthEnc::GCM->new('AES', $key, $iv);
  my $ct  = unpack('H*', $ae->encrypt_add($text));
  my $tag = unpack('H*', $ae->encrypt_done());
  return $iv . $tag . $ct;    # This is $encrypted in decrypt.
}

signature_for decrypt => (
  method     => false,
  positional => [ NonEmptyStr, Key ],
  returns    => NonEmptyStr,
);

sub decrypt ($encrypted, $key) {
  my $iv      = substr $encrypted, 0, $GL::Crypt::IV::LENGTH;
  my $tag     = substr $encrypted, $GL::Crypt::IV::LENGTH, $TAG_LENGTH;
  my $ct      = substr $encrypted, $GL::Crypt::IV::LENGTH + $TAG_LENGTH;
  my $ae      = Crypt::AuthEnc::GCM->new('AES', $key, $iv);
  my $text    = $ae->decrypt_add(pack('H*', $ct));
  my $tag_out = $ae->decrypt_done();
  croak 'bad decrypt' if unpack('H*', $tag_out) ne $tag;
  return $text;
}

our @EXPORT_OK   = qw ( decrypt encrypt );
our %EXPORT_TAGS = (all => [qw( decrypt encrypt )]);

__END__

