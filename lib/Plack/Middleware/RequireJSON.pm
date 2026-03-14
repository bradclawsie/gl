package Plack::Middleware::RequireJSON;
use v5.42;
use strictures 2;
use parent 'Plack::Middleware';

our $VERSION   = '0.0.1';
our $AUTHORITY = 'cpan:bclawsie';

sub call ($self, $env) {
  my $method = $env->{REQUEST_METHOD};
  if ($method eq 'POST' || $method eq 'PUT') {
    my $ct = $env->{CONTENT_TYPE} // q{};
    if ($ct !~ m{\Aapplication/json}xi) {
      return [
        415,
        [ 'Content-Type' => 'text/plain' ],
        ['Content-Type must be application/json'],
      ];
    }
  }

  return $self->app->($env);
}

__END__
