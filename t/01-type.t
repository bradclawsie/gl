use v5.42;
use strictures 2;
use English                 qw(-no_match_vars);
use Test2::V0               qw( done_testing note ok subtest );
use Test2::Tools::Exception qw( dies lives );
use GL::Crypt::IV           qw( random_iv );
use GL::Crypt::Key          qw( random_key );
use GL::Attribute           qw(
  $ROLE_ADMIN
  $ROLE_NORMAL
  $ROLE_TEST
  $STATUS_ACTIVE
  $STATUS_INACTIVE
  $STATUS_UNCONFIRMED
);
use GL::Type qw( assert_IV assert_Key assert_Role assert_Status );

our $VERSION   = '0.01';
our $AUTHORITY = 'cpan:bclawsie';

subtest 'IV' => sub {
  ok(
    lives {
      assert_IV(random_iv);
    },
  'IV lives') or note($EVAL_ERROR);

  ok(
    dies {
      assert_IV(q{});
    },
  'IV dies') or note($EVAL_ERROR);
};

subtest 'Key' => sub {
  ok(
    lives {
      assert_Key(random_key);
    },
  'Key lives') or note($EVAL_ERROR);

  ok(
    dies {
      assert_Key(q{});
    },
  'Key dies') or note($EVAL_ERROR);
};

subtest 'Role' => sub {
  ok(
    lives {
      assert_Role($ROLE_NORMAL);
      assert_Role($ROLE_ADMIN);
      assert_Role($ROLE_TEST);
    },
  'Role lives') or note($EVAL_ERROR);

  ok(
    dies {
      assert_Role(0);
    },
  'Role dies') or note($EVAL_ERROR);
};

subtest 'Status' => sub {
  ok(
    lives {
      assert_Status($STATUS_UNCONFIRMED);
      assert_Status($STATUS_ACTIVE);
      assert_Status($STATUS_INACTIVE);
    },
  'Status lives') or note($EVAL_ERROR);

  ok(
    dies {
      assert_Status(0);
    },
  'Status dies') or note($EVAL_ERROR);
};

done_testing;

__END__
