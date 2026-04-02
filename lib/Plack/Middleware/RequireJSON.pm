package Plack::Middleware::RequireJSON;
use v5.42;
use strictures 2;
use parent 'Plack::Middleware';
use JSON::MaybeXS  qw( decode_json );
use Plack::Request ();

use GL::HTTP qw( http_err );

our $VERSION   = '0.0.1';
our $AUTHORITY = 'cpan:bclawsie';

sub call ($self, $env) {
  my $method = $env->{REQUEST_METHOD};
  if ($method eq 'POST' || $method eq 'PUT') {
    my $ct = $env->{CONTENT_TYPE} // q{};
    return http_err(415, q{'Content-Type' must be 'application/json'})
      if ($ct !~ m{\Aapplication/json}xi);

    my $req = Plack::Request->new($env);

    my $payload;
    try {
      $payload = decode_json($req->content);
    }
    catch ($e) {
      return http_err(400, q{body is not acceptable JSON});
    }

    $env->{'psgix.payload'} = $payload;
  }

  return $self->app->($env);
}

__END__
