use v5.42;
use strictures 2;
use Crypt::Misc             qw( random_v4uuid );
use English                 qw(-no_match_vars);
use Test2::V0               qw( done_testing is note ok subtest );
use Test2::Tools::Compare   qw( like );
use Test2::Tools::Exception qw( lives );
use Time::Piece             qw( localtime );

use GL::Runtime::Test        ();
use GL::Runtime::Development ();
use GL::Type                 qw( Key );

subtest 'test db' => sub {
  my $rt = GL::Runtime::Test->new;

  ok(
    lives {
      is('test', $rt->mode, 'mode is test');
      my $c = $rt->db->run(
        ping => sub {
          $_->selectrow_array('select count(*) from user');
        }
      );
      is(0, $c, 'table is empty');
    },
    'runtime lives'
  ) or note($EVAL_ERROR);
};

subtest 'development db' => sub {
  my $rt = GL::Runtime::Development->new;

  ok(
    lives {
      is('development', $rt->mode, 'mode is development');
      my $c = $rt->db->run(
        ping => sub {
          $_->selectrow_array('select count(*) from user');
        }
      );
      like($c, qr/^\d+$/, 'table has rows');
    },
    'runtime lives'
  ) or note($EVAL_ERROR);
};

subtest 'get_key' => sub {
  my $rt = GL::Runtime::Test->new;

  ok(
    lives {
      Key->check($rt->get_key->($rt->encryption_key_version));
    },
    'get_key lives'
  ) or note($EVAL_ERROR);

  ok(
    lives {
      my $caught = false;
      try {
        $rt->get_key->(random_v4uuid);
      }
      catch ($e) {
        like($e, qr/bad key_version/, 'matched bad key exception');
        $caught = true;
      }
      ok($caught, 'caught bad key exception');
    },
    'get_key lives'
  ) or note($EVAL_ERROR);
};

subtest 'logger' => sub {
  my $rt = GL::Runtime::Test->new;

  ok(
    lives {
      my $s = '0';
      $rt->log->debug($s);
      is(1, scalar @{$rt->log->output('test')->array}, 'single log line');
    },
    'logger lives'
  ) or note($EVAL_ERROR);
};

subtest 'started_at' => sub {
  my $rt = GL::Runtime::Test->new;

  my $now  = localtime;
  my $diff = $now - $rt->started_at;
  ok($diff->seconds >= 0, 'positive time diff');
};

done_testing;

__END__
