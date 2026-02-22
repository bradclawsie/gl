use v5.42;
use strictures 2;
use Carp                  qw( croak );
use Crypt::Misc           qw( is_v4uuid random_v4uuid );
use English               qw(-no_match_vars);
use HTTP::Request::Common qw( GET POST );
use Path::Tiny            qw( path );
use Plack::Builder        qw( builder enable mount );
use Plack::Test;
use Plack::Util;
use Test2::V0               qw( done_testing is note ok subtest );
use Test2::Tools::Exception qw( lives );

use GL::Runtime::Test ();

our $VERSION   = '0.01';
our $AUTHORITY = 'cpan:bclawsie';

subtest 'token post ok' => sub {
  ok(
    lives {
      my $rt = GL::Runtime::Test->new;

      my $psgi_path  = $ENV{PSGI_PATH} // croak 'PSGI_PATH';
      my $token_psgi = path($psgi_path, 'token.psgi');
      my $token_app  = Plack::Util::load_psgi($token_psgi);

      my $app = builder {

        # Add runtime to $env.
        enable sub ($app) {
          return sub ($env) {
            $env->{'rt'} = $rt;
            return $app->($env);
          };
        };

        mount '/token' => $token_app;
      };

      my $test = Plack::Test->create($app);

      my $res = $test->request(GET '/token');
      is(405, $res->code, 'match method fail');

      $res = $test->request(POST '/token');
      is(200, $res->code, 'match method');
    },
    'token post ok lives'
  ) or note($EVAL_ERROR);
};

done_testing;

__END__
