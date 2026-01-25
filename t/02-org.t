use v5.42;
use strictures 2;
use English                 qw(-no_match_vars);
use Test2::V0               qw( done_testing note ok subtest );
use Test2::Tools::Exception qw( dies lives );
use GL::Org                 ();

our $VERSION   = '0.01';
our $AUTHORITY = 'cpan:bclawsie';

subtest 'valid Org' => sub {
  ok(
    lives {
      GL::Org->random;
    },
  ) or note($EVAL_ERROR);

  done_testing;
};

subtest 'invalid attr mutations' => sub {

  ok(
    dies {
      GL::User->random->name(q{});
    },
  ) or note($EVAL_ERROR);

  done_testing;
};

done_testing;
