use v5.42;
use strictures 2;
use Crypt::Misc             qw( random_v4uuid );
use English                 qw(-no_match_vars);
use Test2::V0               qw( done_testing is note ok subtest );
use Test2::Tools::Compare   qw( like );
use Test2::Tools::Exception qw( dies lives );
use Types::UUID             qw( Uuid );

use GL::Org           ();
use GL::Runtime::Test ();

our $VERSION   = '0.01';
our $AUTHORITY = 'cpan:bclawsie';

subtest 'valid Org' => sub {
  ok(
    lives {
      GL::Org->random;
      my $id = random_v4uuid;
      is($id, GL::Org->random(id => $id)->id);
    },
  ) or note($EVAL_ERROR);

  done_testing;
};

subtest 'invalid attr mutations' => sub {

  ok(
    dies {
      GL::Org->random->name(q{});
    },
  ) or note($EVAL_ERROR);

  done_testing;
};

subtest 'insert' => sub {
  ok(
    lives {
      my $now = time;
      my $rt  = GL::Runtime::Test->new;
      my $org = GL::Org->random;
      $org->owner->key_version($rt->encryption_key_version);
      $org->insert($rt->db, $rt->get_key);
      ok($org->ctime >= $now);
      ok($org->mtime >= $now);
      is(1, $org->insert_order);
      ok(Uuid->check($org->signature));
    },
  ) or note($EVAL_ERROR);

  done_testing;
};

subtest 'read' => sub {
  ok(
    lives {
      my $rt  = GL::Runtime::Test->new;
      my $org = GL::Org->random;
      $org->owner->key_version($rt->encryption_key_version);
      $org->insert($rt->db, $rt->get_key);

      my $read_org = GL::Org->read($rt->db, $rt->get_key, $org->id);
      $org->owner->clear_ed25519_private;
      is($read_org, $org);
    },
  ) or note($EVAL_ERROR);

  done_testing;
};

subtest 'read miss' => sub {
  ok(
    lives {
      my $caught = false;
      try {
        my $rt = GL::Runtime::Test->new;
        GL::Org->read($rt->db, $rt->get_key, random_v4uuid);
      }
      catch ($e) {
        like($e, qr/not found/);
        $caught = true;
      }
      ok($caught);
    },
  ) or note($EVAL_ERROR);

  done_testing;
};

done_testing;
