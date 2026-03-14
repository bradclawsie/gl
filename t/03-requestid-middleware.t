use v5.42;
use strictures 2;
use English                 qw(-no_match_vars);
use HTTP::Request           ();
use Plack::Builder          qw( builder enable mount );
use Plack::Test             ();
use Test2::V0               qw( done_testing is note ok subtest );
use Test2::Tools::Exception qw( lives );

our $VERSION   = '0.0.1';
our $AUTHORITY = 'cpan:bclawsie';

subtest 'require json ok' => sub {
  ok(
    lives {
      my $app = builder {
        enable 'RequireJSON';

        mount qw{/} => sub { return [ 200, [], [qw{}] ] };
      };

      my $test = Plack::Test->create($app);

      my $res = $test->request(
        HTTP::Request->new('POST', qw{/}, [ 'Content-Type' => 'text/plain' ]));
      is(415, $res->code, 'match content-type fail');

      $res = $test->request(
        HTTP::Request->new(
          'POST', qw{/}, [ 'Content-Type' => 'application/json' ]
        )
      );
      is(200, $res->code, 'match content-type');

      $res = $test->request(
        HTTP::Request->new('PUT', qw{/}, [ 'Content-Type' => 'text/plain' ]));
      is(415, $res->code, 'match content-type fail');

      $res = $test->request(
        HTTP::Request->new(
          'PUT', qw{/}, [ 'Content-Type' => 'application/json' ]
        )
      );
      is(200, $res->code, 'match content-type');

      $res = $test->request(
        HTTP::Request->new('GET', qw{/}, [ 'Content-Type' => 'text/plain' ]));
      is(200, $res->code, 'bypass middleware');

      $res = $test->request(
        HTTP::Request->new(
          'GET', qw{/}, [ 'Content-Type' => 'application/json' ]
        )
      );
      is(200, $res->code, 'bypass middleware');
    },
    'request json lives'
  ) or note($EVAL_ERROR);
};

done_testing;

__END__
