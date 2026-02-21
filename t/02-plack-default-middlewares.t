use v5.42;
use strictures 2;
use Carp                  qw( croak );
use Crypt::Misc           qw( is_v4uuid random_v4uuid );
use English               qw(-no_match_vars);
use HTTP::Request::Common qw( GET );
use Plack::Builder        qw( builder enable );
use Plack::Test;
use Test2::V0               qw( done_testing is note ok subtest );
use Test2::Tools::Exception qw( lives );

use GL::LogLine       ();
use GL::Runtime::Test ();

our $VERSION   = '0.01';
our $AUTHORITY = 'cpan:bclawsie';

subtest 'default middlewares' => sub {
  ok(
    lives {
      my $rt = GL::Runtime::Test->new;

      my $handler = sub ($env) {
        my $request_id = $env->{'psgix.request_id'};
        $rt->log->debug($request_id);
        return [ 200, [ 'Content-Type' => 'text/plain' ], ['ok'] ];
      };

      my $app = builder {
        enable 'LogDispatch', logger       => $rt->log;
        enable 'RequestId',   id_generator => sub { random_v4uuid };
        $handler;
      };

      my $test = Plack::Test->create($app);
      my $res  = $test->request(GET "/");

      is('ok', $res->content, 'match content');
      ok(is_v4uuid($res->header('X-Request-Id')), 'request id is uuid');
      my $logline = $rt->log->output('test')->array->[-1];
      is(
        $res->header('X-Request-Id'),
        GL::LogLine->parse($logline->{message})->message,
        'match request id'
      );
    },
    'default middlewares lives'
  ) or note($EVAL_ERROR);
};

done_testing;

__END__
