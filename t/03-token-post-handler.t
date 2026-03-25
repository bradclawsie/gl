use v5.42;
use strictures 2;
use Carp                    qw( croak );
use Crypt::Misc             qw( random_v4uuid );
use Crypt::PK::Ed25519      ();
use English                 qw(-no_match_vars);
use HTTP::Request           ();
use JSON::MaybeXS           qw( decode_json encode_json );
use Path::Tiny              qw( path );
use Plack::Builder          qw( builder enable mount );
use Plack::Test             ();
use Plack::Util             ();
use Test2::V0               qw( done_testing is note ok subtest );
use Test2::Tools::Exception qw( lives );

use GL::Attribute     qw( $X_GROKLOC_ID );
use GL::Crypt::JWT    ();
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

  enable 'RequestId', id_generator => sub { random_v4uuid };

  enable 'ValidateCaller';

  enable 'RequireJSON';

  mount q{/} => $token_app;
};

my $test = Plack::Test->create($app);

subtest 'token post ok' => sub {
  ok(
    lives {
      my $priv = Crypt::PK::Ed25519->new(\$user->ed25519_private);
      my $req  = HTTP::Request->new(
        POST => q{/},
        [
          $X_GROKLOC_ID  => $user->id,
          'Content-Type' => 'application/json',
        ],
        encode_json(
          {
            proof => unpack('H*', $priv->sign_message($user->{id})),
          }
        ),
      );
      my $res = $test->request($req);

      is(200, $res->code, 'post ok');
      my $content_json = decode_json($res->content);
      my $jwt = GL::Crypt::JWT->decode($content_json->{token}, $rt->token_key);
      is($user->{id}, $jwt->sub, 'sub and id match');
    },
    'token post ok lives'
  ) or note($EVAL_ERROR);
};

subtest 'bad method' => sub {
  ok(
    lives {
      my $res = $test->request(
        HTTP::Request->new(
          'GET', q{/},
          [
            $X_GROKLOC_ID  => $user->id,
            'Content-Type' => 'application/json',
          ],
        )
      );
      is(405, $res->code, 'match method fail');
    },
    'bad method'
  ) or note($EVAL_ERROR);
};

subtest 'payload missing proof' => sub {
  ok(
    lives {
      my $req = HTTP::Request->new(
        POST => q{/},
        [
          $X_GROKLOC_ID  => $user->id,
          'Content-Type' => 'application/json',
        ],
        encode_json({}),
      );
      my $res = $test->request($req);

      is(400, $res->code, 'payload missing proof code');
      is(q{'proof' must be set in payload},
        $res->content, 'payload missing proof content');
    },
    'payload missing proof lives'
  ) or note($EVAL_ERROR);
};

subtest 'bad proof' => sub {
  ok(
    lives {
      my $priv = Crypt::PK::Ed25519->new(\$user->ed25519_private);
      my $req  = HTTP::Request->new(
        POST => q{/},
        [
          $X_GROKLOC_ID  => $user->id,
          'Content-Type' => 'application/json',
        ],
        encode_json(
          {
            proof => unpack('H*', $priv->sign_message(random_v4uuid)),
          }
        ),
      );
      my $res = $test->request($req);

      is(401, $res->code, 'bad proof code');
      is(q{authentication proof not verified},
        $res->content, 'bad proof content');
    },
    'bad proof ok lives'
  ) or note($EVAL_ERROR);
};

done_testing;

__END__
