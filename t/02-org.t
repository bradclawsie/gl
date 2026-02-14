use v5.42;
use strictures 2;
use Crypt::Misc             qw( random_v4uuid );
use English                 qw(-no_match_vars);
use Test2::V0               qw( done_testing is note ok subtest );
use Test2::Tools::Compare   qw( like );
use Test2::Tools::Exception qw( dies lives );
use Types::UUID             qw( Uuid );

use GL::Attribute     qw( $STATUS_INACTIVE );
use GL::Org           ();
use GL::User          ();
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

subtest 'insert conflict name' => sub {
  ok(
    lives {
      my $rt   = GL::Runtime::Test->new;
      my $org0 = GL::Org->random;
      $org0->owner->key_version($rt->encryption_key_version);
      $org0->insert($rt->db, $rt->get_key);

      my $caught = false;
      try {
        my $org = GL::Org->random(name => $org0->name);
        $org->owner->key_version($rt->encryption_key_version);
        $org->insert($rt->db, $rt->get_key);
      }
      catch ($e) {
        like($e, qr/UNIQUE constraint failed: org.name/);
        $caught = true;
      }
      ok($caught);
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

subtest 'update owner' => sub {
  ok(
    lives {
      my $rt  = GL::Runtime::Test->new;
      my $org = GL::Org->random;
      $org->owner->key_version($rt->encryption_key_version);
      $org->insert($rt->db, $rt->get_key);
      my $user = GL::User->random(
        key_version => $rt->encryption_key_version,
        org         => $org->id,
      );
      $user->insert($rt->db, $rt->get_key);
      $org->update_owner($rt->db, $rt->get_key, $user->id);
    },
  ) or note($EVAL_ERROR);

  done_testing;
};

subtest 'update owner not in org' => sub {
  ok(
    lives {
      my $rt  = GL::Runtime::Test->new;
      my $org = GL::Org->random;
      $org->owner->key_version($rt->encryption_key_version);
      $org->insert($rt->db, $rt->get_key);

      # Org is set to be random, so not $org->id.
      my $user = GL::User->random(key_version => $rt->encryption_key_version);
      $user->insert($rt->db, $rt->get_key);

      my $caught = false;
      try {
        $org->update_owner($rt->db, $rt->get_key, $user->id);
      }
      catch ($e) {
        like($e, qr/bad owner/);
        $caught = true;
      }
      ok($caught);
    },
  ) or note($EVAL_ERROR);

  done_testing;
};

subtest 'update owner not active' => sub {
  ok(
    lives {
      my $rt  = GL::Runtime::Test->new;
      my $org = GL::Org->random;
      $org->owner->key_version($rt->encryption_key_version);
      $org->insert($rt->db, $rt->get_key);
      my $user = GL::User->random(
        key_version => $rt->encryption_key_version,
        org         => $org->id,
        status      => $STATUS_INACTIVE,
      );
      $user->insert($rt->db, $rt->get_key);

      my $caught = false;
      try {
        $org->update_owner($rt->db, $rt->get_key, $user->id);
      }
      catch ($e) {
        like($e, qr/bad owner/);
        $caught = true;
      }
      ok($caught);
    },
  ) or note($EVAL_ERROR);

  done_testing;
};

subtest 'update owner not found' => sub {
  ok(
    lives {
      my $rt  = GL::Runtime::Test->new;
      my $org = GL::Org->random;
      $org->owner->key_version($rt->encryption_key_version);
      $org->insert($rt->db, $rt->get_key);

      my $caught = false;
      try {
        $org->update_owner($rt->db, $rt->get_key, random_v4uuid);
      }
      catch ($e) {
        like($e, qr/bad owner/);
        $caught = true;
      }
      ok($caught);
    },
  ) or note($EVAL_ERROR);

  done_testing;
};

subtest 'users' => sub {
  ok(
    lives {
      my $rt  = GL::Runtime::Test->new;
      my $org = GL::Org->random;
      $org->owner->key_version($rt->encryption_key_version);
      $org->insert($rt->db, $rt->get_key);

      for (0 .. 9) {    # Ten users + one owner = eleven total.
        my $user = GL::User->random(
          key_version => $rt->encryption_key_version,
          org         => $org->id,
        );
        $user->insert($rt->db, $rt->get_key);
      }

      my $limit             = 5;
      my $last_insert_order = 0;
      my %count_ids         = ();
      my $count_calls       = 0;
      while (true) {
        my $batch = $org->users(
          $rt->db,
          limit             => $limit,
          last_insert_order => $last_insert_order
        );
        is('ARRAY', ref($batch));
        last unless (scalar @{$batch});
        map { $count_ids{$_->{id}}++ } @{$batch};
        $last_insert_order = $batch->[-1]->{insert_order};
        $count_calls++;
      }
      is(3,  $count_calls);             # Two batches of five, one batch of one.
      is(11, scalar keys %count_ids);
    },
  ) or note($EVAL_ERROR);

  done_testing;
};

done_testing;
