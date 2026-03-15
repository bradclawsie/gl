package Plack::Middleware::ValidateCaller;
use v5.42;
use strictures 2;
use parent 'Plack::Middleware';
use Plack::Request  ();
use Plack::Response ();

use GL::Attribute qw( $X_GROKLOC_ID );

our $VERSION   = '0.0.1';
our $AUTHORITY = 'cpan:bclawsie';

# Validate the caller and populate $env with caller User and Org.
sub call ($self, $env) {
  my $req = Plack::Request->new($env);

  unless (defined $req->header($X_GROKLOC_ID)) {
    my $res = Plack::Response->new(400);
    $res->content_type('text/plain');
    $res->body("missing $X_GROKLOC_ID header");
    return $res->finalize;
  }

  return $self->app->($env);
}

__END__
