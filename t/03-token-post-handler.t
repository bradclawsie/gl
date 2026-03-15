use v5.42;
use strictures 2;
use Carp                    qw( croak );
use Crypt::PK::Ed25519      ();
use English                 qw(-no_match_vars);
use HTTP::Request           ();
use HTTP::Request::Common   qw( GET );
use JSON::MaybeXS           qw( encode_json );
use Path::Tiny              qw( path );
use Plack::Builder          qw( builder enable mount );
use Plack::Test             ();
use Plack::Util             ();
use Test2::V0               qw( done_testing is note ok subtest );
use Test2::Tools::Exception qw( lives );

use GL::Test          qw( org_with_user );
use GL::Runtime::Test ();

our $VERSION   = '0.0.1';
our $AUTHORITY = 'cpan:bclawsie';

my $rt = GL::Runtime::Test->new;
my ($org, $user) = org_with_user($rt);

my $psgi_path  = $ENV{PSGI_PATH} // croak 'PSGI_PATH';
my $token_psgi = path($psgi_path, 'token.psgi');
my $token_app  = Plack::Util::load_psgi($token_psgi);

my $app = builder {

  # Add runtime to $env.
  enable sub ($app) {
    return sub ($env) {
      $env->{rt} = $rt;
      return $app->($env);
    };
  };

  mount '/token' => $token_app;
};

my $test = Plack::Test->create($app);

subtest 'token post ok' => sub {
  ok(
    lives {
      my $priv = Crypt::PK::Ed25519->new(\$user->ed25519_private);
      my $req  = HTTP::Request->new(
        POST => '/token',
        [ 'Content-Type' => 'application/json' ],
        encode_json(
          {
            id    => $user->{id},
            proof => unpack('H*', $priv->sign_message($user->{id})),
          }
        ),
      );
      my $res = $test->request($req);

      is(200, $res->code, 'post ok');
    },
    'token post ok lives'
  ) or note($EVAL_ERROR);
};

subtest 'bad method' => sub {
  ok(
    lives {
      my $res = $test->request(GET '/token');
      is(405, $res->code, 'match method fail');
    },
    'bad method'
  ) or note($EVAL_ERROR);
};

done_testing;

__END__
