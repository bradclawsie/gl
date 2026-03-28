# vim: set filetype=perl :
use v5.42;
use strictures 2;
use Carp            qw( croak );
use Crypt::Misc     qw( random_v4uuid );
use Module::Load    qw( load );
use Path::Tiny      qw( path );
use Plack::Builder  qw( builder enable mount );
use Plack::Response ();
use Plack::Util     ();

our $VERSION   = '0.0.1';
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

my $psgi_path = $ENV{PSGI_PATH} // croak 'PSGI_PATH';
my $token_app = Plack::Util::load_psgi(path($psgi_path, 'token.psgi'));

my $default_app = sub {
  my $res = Plack::Response->new(404);
  $res->content_type('text/plain');
  $res->body('not found');
  return $res->finalize;
};

builder {
  # Add runtime to $env.
  enable sub ($app) {
    return sub ($env) {
      $env->{rt} = $rt;
      return $app->($env);
    };
  };

  enable 'RequestId', id_generator => sub { random_v4uuid };

  mount q{/token} => builder {
    enable 'ValidateCaller';
    enable 'RequireJSON';

    $token_app;
  };

  # 404 handler
  mount q{/} => $default_app;
};

__END__
