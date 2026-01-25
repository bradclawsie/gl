package GL::Attribute;
use v5.42;
use strictures 2;
use Exporter qw( import );
use Readonly ();

our $VERSION   = '0.0.1';
our $AUTHORITY = 'cpan:bclawsie';

Readonly::Scalar our $DATE => '%Y-%m-%d %H:%M:%S GMT';

Readonly::Scalar our $DATE_RE => qr{^
  \d{4}-
  \d{2}-
  \d{2}\s
  \d{2}:
  \d{2}:
  \d{2}\s
  GMT
  $}x;

Readonly::Scalar our $ROLE_NORMAL        => 1;
Readonly::Scalar our $ROLE_ADMIN         => 2;
Readonly::Scalar our $ROLE_TEST          => 3;
Readonly::Scalar our $STATUS_UNCONFIRMED => 1;
Readonly::Scalar our $STATUS_ACTIVE      => 2;
Readonly::Scalar our $STATUS_INACTIVE    => 3;

our @EXPORT_OK =
  qw( $DATE $DATE_RE $ROLE_NORMAL $ROLE_ADMIN $ROLE_TEST $STATUS_UNCONFIRMED $STATUS_ACTIVE $STATUS_INACTIVE );
our %EXPORT_TAGS = (
  all => [
    qw( $DATE $DATE_RE $ROLE_NORMAL $ROLE_ADMIN $ROLE_TEST $STATUS_UNCONFIRMED $STATUS_ACTIVE $STATUS_INACTIVE )
  ]
);

__END__

