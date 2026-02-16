# vim: set filetype=perl :
use v5.42;
use strictures 2;
use Carp           qw( croak );
use Module::Load   qw( load );
use Plack::Builder qw( builder mount );

our $VERSION   = '0.01';
our $AUTHORITY = 'cpan:bclawsie';

my $env = $ENV{PLACK_ENV} || croak 'PLACK_ENV not set';
my $rt_pkg;
if ($env eq 'test') {
  $rt_pkg = 'GL::Runtime::Test';
}
elsif ($env eq 'development') {
  $rt_pkg = 'GL::Runtime::Development';
}
else {
  croak 'unsupported env';
}
load $rt_pkg;
my $rt = $rt_pkg->new;

my $default_app = sub {
  return [ 404, [ 'Content-Type', 'text/plain' ], ['not found'] ];
};

builder {
  # api.psgi will have the Module::Load stuff as it requires a runtime
  # mount '/api' => Plack::Util::load_psgi('./api.psgi');
  #
  # token creation
  # mount '/token' => Plack::Util::load_psgi('./token.psgi');
  #
  # non-authenticated pages
  # mount '/server' => Plack::Util::load_psgi('./server.psgi');
  #
  mount q{/} => $default_app;
};

__END__
