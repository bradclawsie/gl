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
      my $org = GL::Org->random;
      $org->owner->key_version($rt->encryption_key_version);
      $org->insert($rt->db, $rt->get_key);
      ok($org->ctime >= $now, 'valid ctime');
      ok($org->mtime >= $now, 'valid mtime');
      is(1, $org->insert_order, 'insert_order match');
      ok(Uuid->check($org->signature), 'signature is Uuid');
    },
    'insert lives'
  ) or note($EVAL_ERROR);
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
        like(
          $e,
          qr/UNIQUE constraint failed: org.name/,
          'matched constraint exception'
        );
        $caught = true;
      }
      ok($caught, 'caught insert exception');
    },
    'insert constraint lives'
  ) or note($EVAL_ERROR);
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
      is($read_org, $org, 'org name matches');
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
  ) or note($EVAL_ERROR);
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
    'update owner lives'
  ) or note($EVAL_ERROR);
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
        like($e, qr/bad owner/, 'matched bad owner exception');
        $caught = true;
      }
      ok($caught, 'caught bad owner exception');
    },
    'update bad owner lives'
  ) or note($EVAL_ERROR);
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
        like($e, qr/bad owner/, 'matched bad owner exception');
        $caught = true;
      }
      ok($caught, 'caught bad owner exception');
    },
    'update bad owner lives'
  ) or note($EVAL_ERROR);
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
        like($e, qr/bad owner/, 'matched bad owner exception');
        $caught = true;
      }
      ok($caught, 'caught bad owner exception');
    },
    'update bad owner lives'
  ) or note($EVAL_ERROR);
};

subtest 'users' => sub {
  ok(
    lives {
      my $rt  = GL::Runtime::Test->new;
      my $org = GL::Org->random;
      $org->owner->key_version($rt->encryption_key_version);
      $org->insert($rt->db, $rt->get_key);    # Has one owner user already.

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

done_testing;

__END__
