package Plack::Middleware::WithRuntime;
use v5.42;
use strictures 2;
use parent 'Plack::Middleware';
use Carp qw( croak );

use GL::Type qw( Runtime );

our $VERSION   = '0.0.1';
our $AUTHORITY = 'cpan:bclawsie';

sub call ($self, $env) {
  croak 'no runtime'  unless (defined $self->{runtime});
  croak 'bad runtime' unless (Runtime->check($self->{runtime}));

  $env->{'psgix.runtime'} = $self->{runtime};
  return $self->app->($env);
}

__END__
