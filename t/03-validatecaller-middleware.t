use v5.42;
use strictures 2;
use Crypt::Misc             qw( random_v4uuid );
use English                 qw(-no_match_vars);
use HTTP::Request           ();
use Plack::Builder          qw( builder enable mount );
use Plack::Test             ();
use Test2::V0               qw( done_testing is note ok subtest );
use Test2::Tools::Exception qw( lives );

use GL::Attribute     qw( $X_GROKLOC_ID );
use GL::Test          qw( org_with_user );
use GL::Runtime::Test ();

our $VERSION   = '0.0.1';
our $AUTHORITY = 'cpan:bclawsie';

my $rt = GL::Runtime::Test->new;
my ($org, $user) = org_with_user($rt);

my $app = builder {

  # Add runtime to $env.
  enable sub ($app) {
    return sub ($env) {
      $env->{rt} = $rt;
      return $app->($env);
    };
  };

  enable 'ValidateCaller';

  mount qw{/} => sub { return [ 200, [], [qw{}] ] };
};

my $test = Plack::Test->create($app);

subtest 'validate caller ok' => sub {
  ok(
    lives {
      my $res = $test->request(
        HTTP::Request->new('GET', qw{/}, [ $X_GROKLOC_ID => $user->id ]));
      is(200, $res->code, 'validate caller code');
    },
    'validate caller lives'
  ) or note($EVAL_ERROR);
};

subtest 'missing header' => sub {
  ok(
    lives {
      my $res = $test->request(HTTP::Request->new('GET', qw{/}));
      is(400, $res->code, 'missing header code');
      is("missing $X_GROKLOC_ID header",
        $res->content, 'missing header content');
    },
    'missing header lives'
  ) or note($EVAL_ERROR);
};

subtest 'malformed header' => sub {
  ok(
    lives {
      my $res = $test->request(
        HTTP::Request->new('GET', qw{/}, [ $X_GROKLOC_ID => 'not-uuid' ]));
      is(400, $res->code, 'malformed header code');
      is("malformed $X_GROKLOC_ID header",
        $res->content, 'malformed header content');
    },
    'malformed header lives'
  ) or note($EVAL_ERROR);
};

subtest 'user not found' => sub {
  ok(
    lives {
      my $res = $test->request(
        HTTP::Request->new('GET', qw{/}, [ $X_GROKLOC_ID => random_v4uuid ]));
      is(404,              $res->code,    'user not found code');
      is('user not found', $res->content, 'user not found content');
    },
    'user not found lives'
  ) or note($EVAL_ERROR);
};

done_testing;

__END__
