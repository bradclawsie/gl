use v5.42;
use strictures 2;
use English                 qw(-no_match_vars);
use HTTP::Request           ();
use JSON::MaybeXS           qw( encode_json );
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

        mount q{/} => sub ($env) {
          unless (defined $env->{'psgix.payload'}) {
            return [ 500, [], [q{no payload}] ];
          }
          my $payload = $env->{'psgix.payload'};
          unless (defined $payload->{test}) {
            return [ 400, [], [q{no test key}] ];
          }
          return [ 200, [], [q{}] ];
        };

        mount q{/bypass} => sub {
          return [ 200, [], [q{}] ];
        };
      };

      my $test = Plack::Test->create($app);

      my $res = $test->request(
        HTTP::Request->new('POST', q{/}, [ 'Content-Type' => 'text/plain' ]));
      is(415, $res->code, 'match content-type fail');

      $res = $test->request(
        HTTP::Request->new(
          'POST', q{/},
          [ 'Content-Type' => 'application/json' ],
          encode_json({test => 'test'}),
        )
      );
      is(200, $res->code, 'match content-type');

      $res = $test->request(
        HTTP::Request->new('PUT', q{/}, [ 'Content-Type' => 'text/plain' ]));
      is(415, $res->code, 'match content-type fail');

      $res = $test->request(
        HTTP::Request->new(
          'PUT', q{/},
          [ 'Content-Type' => 'application/json' ],
          encode_json({test => 'test'}),
        )
      );
      is(200, $res->code, 'match content-type');

      $res = $test->request(
        HTTP::Request->new(
          'GET', q{/bypass}, [ 'Content-Type' => 'text/plain' ]
        )
      );
      is(200, $res->code, 'bypass middleware');

      $res = $test->request(
        HTTP::Request->new(
          'GET', q{/bypass}, [ 'Content-Type' => 'application/json' ]
        )
      );
      is(200, $res->code, 'bypass middleware');

      $res = $test->request(
        HTTP::Request->new(
          'POST',                                   q{/},
          [ 'Content-Type' => 'application/json' ], '{"not quite json',
        )
      );
      is(400,                            $res->code,    'match content-type');
      is(q{body is not acceptable JSON}, $res->content, 'match content');

      $res = $test->request(
        HTTP::Request->new(
          'PUT',                                    q{/},
          [ 'Content-Type' => 'application/json' ], '{"not quite json',
        )
      );
      is(400,                            $res->code,    'match content-type');
      is(q{body is not acceptable JSON}, $res->content, 'match content');
    },
    'request json lives'
  ) or note($EVAL_ERROR);
};

done_testing;

__END__
