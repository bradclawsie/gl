use v5.42;
use strictures 2;
use Crypt::Misc             qw( random_v4uuid );
use English                 qw(-no_match_vars);
use Test2::V0               qw( done_testing is note ok subtest );
use Test2::Tools::Exception qw( dies lives );
use GL::Crypt::JWT          ();

our $VERSION   = '0.01';
our $AUTHORITY = 'cpan:bclawsie';

subtest 'encode decode' => sub {
  ok(
    lives {
      my $now = time;
      my $jwt = GL::Crypt::JWT->new(
        exp => $now + 10,
        id  => random_v4uuid,
        iss => 'GrokLOC.com',
        nbf => $now - 10,
        sub => random_v4uuid,
      );
      my $signing_key = random_v4uuid;
      is($jwt,
        GL::Crypt::JWT->decode($jwt->encode($signing_key), $signing_key));
      is(
        $jwt,
        GL::Crypt::JWT->from_header(
          $jwt->to_header($signing_key), $signing_key
        )
      );
    },
  ) or note($EVAL_ERROR);

  done_testing;
};

subtest 'bad exp' => sub {
  ok(
    dies {
      my $now = time;
      GL::Crypt::JWT->new(
        exp => $now - 10,
        id  => random_v4uuid,
        iss => 'GrokLOC.com',
        nbf => $now - 10,
        sub => random_v4uuid,
      );
    },
  ) or note($EVAL_ERROR);

  done_testing;
};

subtest 'bad id' => sub {
  ok(
    dies {
      my $now = time;
      GL::Crypt::JWT->new(
        exp => $now + 10,
        id  => q{},
        iss => 'GrokLOC.com',
        nbf => $now - 10,
        sub => random_v4uuid,
      );
    },
  ) or note($EVAL_ERROR);

  done_testing;
};

subtest 'bad iss' => sub {
  ok(
    dies {
      my $now = time;
      GL::Crypt::JWT->new(
        exp => $now + 10,
        id  => random_v4uuid,
        iss => q{},
        nbf => $now - 10,
        sub => random_v4uuid,
      );
    },
  ) or note($EVAL_ERROR);

  done_testing;
};

subtest 'bad nbf' => sub {
  ok(
    dies {
      my $now = time;
      GL::Crypt::JWT->new(
        exp => $now + 10,
        id  => random_v4uuid,
        iss => 'GrokLOC.com',
        nbf => $now + 10,
        sub => random_v4uuid,
      );
    },
  ) or note($EVAL_ERROR);

  done_testing;
};

subtest 'bad sub' => sub {
  ok(
    dies {
      my $now = time;
      GL::Crypt::JWT->new(
        exp => $now + 10,
        id  => random_v4uuid,
        iss => 'GrokLOC.com',
        nbf => $now - 10,
        sub => q{},
      );
    },
  ) or note($EVAL_ERROR);

  done_testing;
};

done_testing;
