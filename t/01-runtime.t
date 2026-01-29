use v5.42;
use strictures 2;
use Crypt::Misc             qw( random_v4uuid );
use English                 qw(-no_match_vars);
use Test2::V0               qw( done_testing is note ok subtest );
use Test2::Tools::Compare   qw( like );
use Test2::Tools::Exception qw( lives );

use GL::Runtime::Test        ();
use GL::Runtime::Development ();
use GL::Type                 qw( Key );

subtest 'test db' => sub {
  my $rt = GL::Runtime::Test->new;

  ok(
    lives {
      my $c = $rt->db->run(
        ping => sub {
          $_->selectrow_array('select count(*) from user');
        }
      );
      is(0, $c);
    },
  ) or note($EVAL_ERROR);

  done_testing;
};

subtest 'development db' => sub {
  my $rt = GL::Runtime::Development->new;

  ok(
    lives {
      my $c = $rt->db->run(
        ping => sub {
          $_->selectrow_array('select count(*) from user');
        }
      );
      is(0, $c);
    },
  ) or note($EVAL_ERROR);

  done_testing;
};

subtest 'get_key' => sub {
  my $rt = GL::Runtime::Test->new;

  ok(
    lives {
      Key->check($rt->get_key->($rt->encryption_key_version));
    },
  ) or note($EVAL_ERROR);

  ok(
    lives {
      my $caught = false;
      try {
        $rt->get_key->(random_v4uuid);
      }
      catch ($e) {
        like($e, qr/bad key_version/);
        $caught = true;
      }
      ok($caught);
    },
  ) or note($EVAL_ERROR);

  done_testing;
};

done_testing;

__END__
