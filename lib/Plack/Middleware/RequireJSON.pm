package Plack::Middleware::RequireJSON;
use v5.42;
use strictures 2;
use parent 'Plack::Middleware';
use JSON::MaybeXS   qw( decode_json );
use Plack::Request  ();
use Plack::Response ();

our $VERSION   = '0.0.1';
our $AUTHORITY = 'cpan:bclawsie';

sub call ($self, $env) {
  my $method = $env->{REQUEST_METHOD};
  if ($method eq 'POST' || $method eq 'PUT') {
    my $ct = $env->{CONTENT_TYPE} // q{};
    if ($ct !~ m{\Aapplication/json}xi) {
      my $res = Plack::Response->new(415);
      $res->content_type('text/plain');
      $res->body(q{'Content-Type' must be 'application/json'});
      return $res->finalize;
    }

    my $req = Plack::Request->new($env);

    my $payload;
    try {
      $payload = decode_json($req->content);
    }
    catch ($e) {
      my $res = Plack::Response->new(400);
      $res->content_type('text/plain');
      $res->body(q{body is not acceptable JSON});
      return $res->finalize;
    }

    $env->{'psgix.payload'} = $payload;
  }

  return $self->app->($env);
}

__END__
