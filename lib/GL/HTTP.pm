package GL::HTTP;
use v5.42;
use strictures 2;
use Exporter               qw( import );
use Plack::Response        ();
use Type::Params           qw( signature_for );
use Types::Common::Numeric qw( PositiveInt );
use Types::Common::String  qw( NonEmptyStr );
use Types::Standard        qw( Any ArrayRef );

our $VERSION   = '0.0.1';
our $AUTHORITY = 'cpan:bclawsie';

signature_for http_err => (
  method     => false,
  positional => [ PositiveInt, NonEmptyStr ],
  returns    => ArrayRef [Any],
);

sub http_err ($code, $msg) {
  my $res = Plack::Response->new($code);
  $res->content_type('text/plain');
  $res->body($msg);
  return $res->finalize;
}

sub http_fatal {
  my $res = Plack::Response->new(500);
  $res->content_type('text/plain');
  $res->body('internal error');
  return $res->finalize;
}

our @EXPORT_OK   = qw( http_err http_fatal );
our %EXPORT_TAGS = (all => [qw( http_err http_fatal )]);

__END__
