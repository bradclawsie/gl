use v5.42;
use strictures 2;
use Crypt::Misc             qw( random_v4uuid );
use English                 qw(-no_match_vars);
use HTTP::Request           ();
use Plack::Builder          qw( builder enable mount );
use Plack::Test             ();
use Test2::V0               qw( done_testing is note ok subtest );
use Test2::Tools::Exception qw( lives );

use GL::Attribute     qw( $STATUS_INACTIVE $X_GROKLOC_ID );
use GL::Test          qw( org_with_user );
use GL::Runtime::Test ();

our $VERSION   = '0.0.1';
our $AUTHORITY = 'cpan:bclawsie';

my $rt = GL::Runtime::Test->new;
my ($org, $user) = org_with_user($rt);

my $app = builder {
  enable 'WithRuntime', runtime      => $rt;
  enable 'RequestId',   id_generator => sub { random_v4uuid };
  enable 'ValidateCaller';

  mount q{/} => sub ($env) {
    if ( $env->{'psgix.caller_is_root'} == false
      && $env->{'psgix.calling_org'} isa 'GL::Org'
      && $env->{'psgix.calling_user'} isa 'GL::User')
    {
      return [ 200, [], [q{}] ];
    }
    return [ 400, [], [q{}] ];
  };

  mount q{/is_root} => sub ($env) {
    if ( $env->{'psgix.caller_is_root'} == true
      && $env->{'psgix.calling_org'} isa 'GL::Org'
      && $env->{'psgix.calling_user'} isa 'GL::User')
    {
      return [ 200, [], [q{}] ];
    }
    return [ 400, [], [q{}] ];
  };
};

my $test = Plack::Test->create($app);

subtest 'validate caller ok' => sub {
  ok(
    lives {
      my $res = $test->request(
        HTTP::Request->new('GET', q{/}, [ $X_GROKLOC_ID => $user->id ]));
      is(200, $res->code, 'validate caller code');
      $res = $test->request(
        HTTP::Request->new('GET', q{/is_root}, [ $X_GROKLOC_ID => $user->id ]));
      is(400, $res->code, 'validate is_root code');
    },
    'validate caller lives'
  ) or note($EVAL_ERROR);
};

subtest 'validate root' => sub {
  ok(
    lives {
      my $res = $test->request(
        HTTP::Request->new(
          'GET', q{/is_root}, [ $X_GROKLOC_ID => $rt->root->owner->id ]
        )
      );
      is(200, $res->code, 'validate root code');
    },
    'validate root lives'
  ) or note($EVAL_ERROR);
};

subtest 'missing header' => sub {
  ok(
    lives {
      my $res = $test->request(HTTP::Request->new('GET', q{/}));
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
        HTTP::Request->new('GET', q{/}, [ $X_GROKLOC_ID => 'not-uuid' ]));
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
        HTTP::Request->new('GET', q{/}, [ $X_GROKLOC_ID => random_v4uuid ]));
      is(404,              $res->code,    'user not found code');
      is('user not found', $res->content, 'user not found content');
    },
    'user not found lives'
  ) or note($EVAL_ERROR);
};

subtest 'user not active' => sub {
  ok(
    lives {
      my (undef, $user) = org_with_user($rt);
      $user->update_status($rt->db, $STATUS_INACTIVE);
      my $res = $test->request(
        HTTP::Request->new('GET', q{/}, [ $X_GROKLOC_ID => $user->id ]));
      is(400,               $res->code,    'user not active code');
      is('user not active', $res->content, 'user not active content');
    },
    'user not active lives'
  ) or note($EVAL_ERROR);
};

subtest 'org not active' => sub {
  ok(
    lives {
      my ($org, $user) = org_with_user($rt);
      $org->update_status($rt->db, $STATUS_INACTIVE);
      my $res = $test->request(
        HTTP::Request->new('GET', q{/}, [ $X_GROKLOC_ID => $user->id ]));
      is(400,              $res->code,    'org not active code');
      is('org not active', $res->content, 'org not active content');
    },
    'org not active lives'
  ) or note($EVAL_ERROR);
};

done_testing;

__END__
