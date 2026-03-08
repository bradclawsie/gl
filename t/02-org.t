use v5.42;
use strictures 2;
use Crypt::Misc             qw( random_v4uuid );
use English                 qw(-no_match_vars);
use Test2::V0               qw( done_testing is note ok subtest );
use Test2::Tools::Compare   qw( like );
use Test2::Tools::Exception qw( dies lives );
use Types::UUID             qw( Uuid );

use GL::Attribute     qw( $STATUS_ACTIVE $STATUS_INACTIVE );
use GL::Org           ();
use GL::User          ();
use GL::Runtime::Test ();

our $VERSION   = '0.0.1';
our $AUTHORITY = 'cpan:bclawsie';

subtest 'valid Org' => sub {
  ok(
    lives {
      GL::Org->random;
      my $id = random_v4uuid;
      is($id, GL::Org->random(id => $id)->id, 'match id');
    },
    'Org lives'
  ) or note($EVAL_ERROR);
};

subtest 'invalid attr mutations' => sub {
  ok(
    dies {
      GL::Org->random->name(q{});
    },
    'name mutation dies'
  ) or note($EVAL_ERROR);
};

subtest 'insert' => sub {
  ok(
    lives {
      my $now = time;
      my $rt  = GL::Runtime::Test->new;
      my $org =
        GL::Org->random(encryption_key_version => $rt->encryption_key_version,)
        ->insert($rt->db, $rt->get_key, $rt->hmac);
      ok($org->ctime >= $now, 'valid ctime');
      ok($org->mtime >= $now, 'valid mtime');
      is(1, $org->insert_order, 'insert_order match');
      ok(Uuid->check($org->signature), 'signature is Uuid');
    },
    'insert lives'
  ) or note($EVAL_ERROR);
};

subtest 'insert_query' => sub {
  ok(
    lives {
      my $now = time;
      my $rt  = GL::Runtime::Test->new;
      my $org =
        GL::Org->random(encryption_key_version => $rt->encryption_key_version,);
      $rt->db->txn(
        fixup => sub ($dbh) {
          $org->insert_query($dbh, $rt->get_key, $rt->hmac);
        }
      );
      ok($org->ctime >= $now, 'valid ctime');
      ok($org->mtime >= $now, 'valid mtime');
      is(1, $org->insert_order, 'insert_order match');
      ok(Uuid->check($org->signature), 'signature is Uuid');
    },
    'insert_query lives'
  ) or note($EVAL_ERROR);
};

subtest 'insert conflict name' => sub {
  ok(
    lives {
      my $rt = GL::Runtime::Test->new;
      my $org0 =
        GL::Org->random(encryption_key_version => $rt->encryption_key_version,)
        ->insert($rt->db, $rt->get_key, $rt->hmac);

      my $caught = false;
      try {
        GL::Org->random(
          encryption_key_version => $rt->encryption_key_version,
          name                   => $org0->name,
        )->insert($rt->db, $rt->get_key, $rt->hmac);
      }
      catch ($e) {
        like(
          $e,
          qr/UNIQUE constraint failed: org.name/,
          'matched constraint exception'
        );
        $caught = true;
      }
      ok($caught, 'caught insert exception');
    },
    'insert conflict name lives'
  ) or note($EVAL_ERROR);
};

subtest 'read' => sub {
  ok(
    lives {
      my $rt = GL::Runtime::Test->new;
      my $org =
        GL::Org->random(encryption_key_version => $rt->encryption_key_version,)
        ->insert($rt->db, $rt->get_key, $rt->hmac);

      my $read_org = GL::Org->read($rt->db, $rt->get_key, $org->id);
      $org->owner->clear_ed25519_private;
      is($read_org, $org, 'read org');
      my $read_owner = GL::User->read($rt->db, $rt->get_key, $org->owner->id);
      is($read_owner, $org->owner);
    },
    'read lives'
  ) or note($EVAL_ERROR);
};

subtest 'read_query' => sub {
  ok(
    lives {
      my $rt = GL::Runtime::Test->new;
      my $org =
        GL::Org->random(encryption_key_version => $rt->encryption_key_version,)
        ->insert($rt->db, $rt->get_key, $rt->hmac);

      my $read_org;
      $rt->db->txn(
        fixup => sub ($dbh) {
          $read_org = GL::Org->read_query($dbh, $rt->get_key, $org->id);
        }
      );
      $org->owner->clear_ed25519_private;
      is($read_org, $org, 'read org');
      my $read_owner = GL::User->read($rt->db, $rt->get_key, $org->owner->id);
      is($read_owner, $org->owner);
    },
    'read lives'
  ) or note($EVAL_ERROR);
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
        like($e, qr/not found/, 'matched not found exception');
        $caught = true;
      }
      ok($caught, 'caught not found exception');
    },
    'read miss lives'
  ) or note($EVAL_ERROR);
};

subtest 'update_owner' => sub {
  ok(
    lives {
      my $rt = GL::Runtime::Test->new;
      my $org =
        GL::Org->random(encryption_key_version => $rt->encryption_key_version,)
        ->insert($rt->db, $rt->get_key, $rt->hmac);
      my $user = GL::User->random(
        encryption_key_version => $rt->encryption_key_version,
        org                    => $org->id,
      )->insert($rt->db, $rt->get_key, $rt->hmac);
      $org->update_owner($rt->db, $rt->get_key, $user->id);
    },
    'update_owner lives'
  ) or note($EVAL_ERROR);
};

subtest 'update_owner_query' => sub {
  ok(
    lives {
      my $rt = GL::Runtime::Test->new;
      my $org =
        GL::Org->random(encryption_key_version => $rt->encryption_key_version,)
        ->insert($rt->db, $rt->get_key, $rt->hmac);
      my $user = GL::User->random(
        encryption_key_version => $rt->encryption_key_version,
        org                    => $org->id,
      )->insert($rt->db, $rt->get_key, $rt->hmac);
      $rt->db->txn(
        fixup => sub ($dbh) {
          $org->update_owner_query($dbh, $rt->get_key, $user->id);
        }
      );
    },
    'update_owner_query lives'
  ) or note($EVAL_ERROR);
};

subtest 'update_owner not in org' => sub {
  ok(
    lives {
      my $rt = GL::Runtime::Test->new;
      my $org =
        GL::Org->random(encryption_key_version => $rt->encryption_key_version,)
        ->insert($rt->db, $rt->get_key, $rt->hmac);

      # Org is set to be $other_org->id, not $org->id.
      my $other_org =
        GL::Org->random(encryption_key_version => $rt->encryption_key_version,)
        ->insert($rt->db, $rt->get_key, $rt->hmac);
      my $user = GL::User->random(
        encryption_key_version => $rt->encryption_key_version,
        org                    => $other_org->id,
      )->insert($rt->db, $rt->get_key, $rt->hmac);

      my $caught = false;
      try {
        $org->update_owner($rt->db, $rt->get_key, $user->id);
      }
      catch ($e) {
        like($e, qr/bad owner/, 'matched bad owner exception');
        $caught = true;
      }
      ok($caught, 'caught bad owner exception');
    },
    'update_owner not in org lives'
  ) or note($EVAL_ERROR);
};

subtest 'update_owner not active' => sub {
  ok(
    lives {
      my $rt = GL::Runtime::Test->new;
      my $org =
        GL::Org->random(encryption_key_version => $rt->encryption_key_version,)
        ->insert($rt->db, $rt->get_key, $rt->hmac);
      my $user = GL::User->random(
        encryption_key_version => $rt->encryption_key_version,
        org                    => $org->id,
        status                 => $STATUS_INACTIVE,
      )->insert($rt->db, $rt->get_key, $rt->hmac);

      my $caught = false;
      try {
        $org->update_owner($rt->db, $rt->get_key, $user->id);
      }
      catch ($e) {
        like($e, qr/bad owner/, 'matched bad owner exception');
        $caught = true;
      }
      ok($caught, 'caught bad owner exception');
    },
    'update bad owner lives'
  ) or note($EVAL_ERROR);
};

subtest 'update_owner not found' => sub {
  ok(
    lives {
      my $rt = GL::Runtime::Test->new;
      my $org =
        GL::Org->random(encryption_key_version => $rt->encryption_key_version,)
        ->insert($rt->db, $rt->get_key, $rt->hmac);

      my $caught = false;
      try {
        $org->update_owner($rt->db, $rt->get_key, random_v4uuid);
      }
      catch ($e) {
        like($e, qr/bad owner/, 'matched bad owner exception');
        $caught = true;
      }
      ok($caught, 'caught bad owner exception');
    },
    'update bad owner lives'
  ) or note($EVAL_ERROR);
};

subtest 'update_status' => sub {
  ok(
    lives {
      my $rt = GL::Runtime::Test->new;
      my $org =
        GL::Org->random(encryption_key_version => $rt->encryption_key_version)
        ->insert($rt->db, $rt->get_key, $rt->hmac);

      is($STATUS_ACTIVE, $org->status, 'match status');
      is($STATUS_ACTIVE, GL::Org->read($rt->db, $rt->get_key, $org->id)->status,
        'match status');
      $org->update_status($rt->db, $STATUS_INACTIVE);
      is($STATUS_INACTIVE, $org->status, 'match status');
      is($STATUS_INACTIVE,
        GL::Org->read($rt->db, $rt->get_key, $org->id)->status,
        'match status');
    },
    'update_status lives'
  ) or note($EVAL_ERROR);

  ok(
    lives {
      my $rt     = GL::Runtime::Test->new;
      my $caught = false;
      try {
        # Org is never inserted, so the update doesn't change a row.
        GL::Org->random(encryption_key_version => $rt->encryption_key_version)
          ->update_status($rt->db, $STATUS_INACTIVE);
      }
      catch ($e) {
        like($e, qr/no rows affected/, 'matched update status exception');
        $caught = true;
      }
      ok($caught, 'caught update status exception');
    },
    'update_status lives'
  ) or note($EVAL_ERROR);
};

subtest 'update_status_query' => sub {
  ok(
    lives {
      my $rt = GL::Runtime::Test->new;
      my $org =
        GL::Org->random(encryption_key_version => $rt->encryption_key_version)
        ->insert($rt->db, $rt->get_key, $rt->hmac);

      $rt->db->txn(
        fixup => sub ($dbh) {
          $org->update_status_query($dbh, $STATUS_INACTIVE);
        }
      );

      is($STATUS_INACTIVE, $org->status, 'match status');
      is($STATUS_INACTIVE,
        GL::Org->read($rt->db, $rt->get_key, $org->id)->status,
        'match status');
      $org->update_status($rt->db, $STATUS_ACTIVE);
      is($STATUS_ACTIVE, $org->status, 'match status');
      is($STATUS_ACTIVE, GL::Org->read($rt->db, $rt->get_key, $org->id)->status,
        'match status');
    },
    'update_status_query lives'
  ) or note($EVAL_ERROR);
};

subtest 'users' => sub {
  ok(
    lives {
      my $rt = GL::Runtime::Test->new;
      my $org =
        GL::Org->random(encryption_key_version => $rt->encryption_key_version,)
        ->insert($rt->db, $rt->get_key, $rt->hmac);

      for (0 .. 9) {    # Ten users + one owner = eleven total.
        my $user = GL::User->random(
          encryption_key_version => $rt->encryption_key_version,
          org                    => $org->id,
        );
        $user->insert($rt->db, $rt->get_key, $rt->hmac);
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
        is('ARRAY', ref($batch), 'users retval is array ref');
        last unless (scalar @{$batch});
        map { $count_ids{$_->{id}}++ } @{$batch};
        $last_insert_order = $batch->[-1]->{insert_order};
        $count_calls++;
      }
      is(3,  $count_calls,           'three users calls');
      is(11, scalar keys %count_ids, 'eleven users total');
    },
    'users lives'
  ) or note($EVAL_ERROR);
};

subtest 'users_query' => sub {
  ok(
    lives {
      my $rt = GL::Runtime::Test->new;
      my $org =
        GL::Org->random(encryption_key_version => $rt->encryption_key_version,)
        ->insert($rt->db, $rt->get_key, $rt->hmac);

      for (0 .. 9) {    # Ten users + one owner = eleven total.
        my $user = GL::User->random(
          encryption_key_version => $rt->encryption_key_version,
          org                    => $org->id,
        );
        $user->insert($rt->db, $rt->get_key, $rt->hmac);
      }

      my $limit             = 5;
      my $last_insert_order = 0;
      my %count_ids         = ();
      my $count_calls       = 0;
      while (true) {
        my $batch;
        $rt->db->txn(
          fixup => sub ($dbh) {
            $batch = $org->users_query(
              $dbh,
              limit             => $limit,
              last_insert_order => $last_insert_order
            );
          }
        );
        is('ARRAY', ref($batch), 'users retval is array ref');
        last unless (scalar @{$batch});
        map { $count_ids{$_->{id}}++ } @{$batch};
        $last_insert_order = $batch->[-1]->{insert_order};
        $count_calls++;
      }
      is(3,  $count_calls,           'three users calls');
      is(11, scalar keys %count_ids, 'eleven users total');
    },
    'users_query lives'
  ) or note($EVAL_ERROR);
};

done_testing;

__END__
