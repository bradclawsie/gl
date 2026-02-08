use v5.42;
use strictures 2;
use Crypt::Digest::SHA256   qw( sha256_hex );
use Crypt::Misc             qw( random_v4uuid );
use Crypt::PK::Ed25519      ();
use English                 qw(-no_match_vars);
use Test2::V0               qw( done_testing is isnt note ok subtest );
use Test2::Tools::Compare   qw( like );
use Test2::Tools::Exception qw( dies lives );
use Types::UUID             qw( Uuid );

use GL::Attribute       qw( $STATUS_ACTIVE $STATUS_INACTIVE );
use GL::Crypt::Password qw( random_password );
use GL::User            ();
use GL::Runtime::Test   ();

our $VERSION   = '0.01';
our $AUTHORITY = 'cpan:bclawsie';

subtest 'valid User' => sub {
  ok(
    lives {
      my $id = random_v4uuid;
      is($id, GL::User->random(id => $id)->id);
    },
  ) or note($EVAL_ERROR);

  ok(
    lives {
      my $u = GL::User->random;
      isnt(undef, $u->ed25519_private);
      isnt(undef, $u->ed25519_public);
    },
  ) or note($EVAL_ERROR);

  ok(
    lives {
      my $name0      = 'name0';
      my $email0     = 'email0@local';
      my $pk         = Crypt::PK::Ed25519->new->generate_key;
      my $public_key = $pk->export_key_pem('public');

      my $u = GL::User->new(
        display_name   => $name0,
        ed25519_public => $public_key,
        email          => $email0,
        org            => random_v4uuid,
        password       => random_password,
      );

      is(undef, $u->ed25519_private);

      is($u->display_name_digest, sha256_hex($name0));
      is($u->email_digest,        sha256_hex($email0));

      my $name1 = 'name1';
      $u->display_name($name1);
      is($u->display_name_digest, sha256_hex($name1));

      is($u->ed25519_public_digest, sha256_hex($u->ed25519_public));
    },
  ) or note($EVAL_ERROR);

  ok(
    lives {
      my $name0      = 'name0';
      my $email0     = 'email0@local';
      my $pk         = Crypt::PK::Ed25519->new->generate_key;
      my $public_key = $pk->export_key_pem('public');

      my $u = GL::User->new(
        display_name   => $name0,
        ed25519_public => $public_key,
        email          => $email0,
        org            => random_v4uuid,
        password       => random_password,
      );

      is($u->ed25519_private,       undef);
      is($u->ed25519_public,        $public_key);
      is($u->ed25519_public_digest, sha256_hex($u->ed25519_public));
    },
  ) or note($EVAL_ERROR);

  done_testing;
};

subtest 'invalid attr mutations' => sub {

  ok(
    dies {
      GL::User->random->display_name_digest(q{});
    },
  ) or note($EVAL_ERROR);

  ok(
    dies {
      GL::User->random->ed25519_public_digest(q{});
    },
  ) or note($EVAL_ERROR);

  ok(
    dies {
      GL::User->random->email_digest(q{});
    },
  ) or note($EVAL_ERROR);

  ok(
    dies {
      GL::User->random->email(q{});
    },
  ) or note($EVAL_ERROR);

  ok(
    dies {
      GL::User->random->password(q{});
    },
  ) or note($EVAL_ERROR);

  done_testing;
};

subtest 'insert' => sub {
  ok(
    lives {
      my $now  = time;
      my $rt   = GL::Runtime::Test->new;
      my $user = GL::User->random(key_version => $rt->encryption_key_version);
      $user->insert($rt->db, $rt->get_key);
      ok($user->ctime >= $now);
      ok($user->mtime >= $now);
      is(1, $user->insert_order);
      ok(Uuid->check($user->signature));
    },

    lives {
      my $caught = false;
      try {
        my $rt   = GL::Runtime::Test->new;
        my $user = GL::User->random;
        $user->insert($rt->db, $rt->get_key);
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

subtest 'insert conflict email' => sub {
  my $rt = GL::Runtime::Test->new;
  my $user0;

  ok(
    lives {
      $user0 = GL::User->random(key_version => $rt->encryption_key_version)
        ->insert($rt->db, $rt->get_key);
    },

    lives {
      my $caught = false;
      try {
        my $user = GL::User->random(
          email       => $user0->email,
          key_version => $rt->encryption_key_version,
          org         => $user0->org,
        )->insert($rt->db, $rt->get_key);
      }
      catch ($e) {
        like($e, qr/UNIQUE constraint failed: user.email_digest, user.org/);
        $caught = true;
      }
      ok($caught);
    },
  ) or note($EVAL_ERROR);

  done_testing;
};

subtest 'insert conflict ed25519_public' => sub {
  my $rt = GL::Runtime::Test->new;
  my $user0;

  ok(
    lives {
      $user0 = GL::User->random(key_version => $rt->encryption_key_version)
        ->insert($rt->db, $rt->get_key);
    },

    lives {
      my $caught = false;
      try {
        my $user = GL::User->random(
          key_version => $rt->encryption_key_version,
          org         => $user0->org,
        );
        $user->ed25519($user0->ed25519_public, undef);
        $user->insert($rt->db, $rt->get_key);
      }
      catch ($e) {
        like($e,
          qr/UNIQUE constraint failed: user.ed25519_public_digest, user.org/);
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
      my $now  = time;
      my $rt   = GL::Runtime::Test->new;
      my $user = GL::User->random(key_version => $rt->encryption_key_version);
      $user->insert($rt->db, $rt->get_key);

      my $read_user = GL::User->read($rt->db, $rt->get_key, $user->id);
      $user->clear_ed25519_private;
      $read_user->clear_ed25519_private;
      is($user, $read_user);
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
        GL::User->read($rt->db, $rt->get_key, random_v4uuid);
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

subtest 'update display name' => sub {
  ok(
    lives {
      my $rt           = GL::Runtime::Test->new;
      my $display_name = random_v4uuid;
      my $user =
        GL::User->random(key_version => $rt->encryption_key_version)
        ->insert($rt->db, $rt->get_key);

      $user->update_display_name($rt->db, $rt->get_key, $display_name);
      is($display_name,             $user->display_name);
      is(sha256_hex($display_name), $user->display_name_digest);

      my $read_user = GL::User->read($rt->db, $rt->get_key, $user->id);
      is($display_name,             $read_user->display_name);
      is(sha256_hex($display_name), $read_user->display_name_digest);
    },

    lives {
      my $rt     = GL::Runtime::Test->new;
      my $caught = false;
      try {
        # User is never inserted, so the update doesn't change a row.
        my $user = GL::User->random(key_version => $rt->encryption_key_version)
          ->update_display_name($rt->db, $rt->get_key, random_v4uuid);
      }
      catch ($e) {
        like($e, qr/no rows affected/);
        $caught = true;
      }
      ok($caught);
    },
  ) or warn($EVAL_ERROR);

  done_testing;
};

subtest 'update ed25519 public' => sub {
  ok(
    lives {
      my $rt         = GL::Runtime::Test->new;
      my $pk         = Crypt::PK::Ed25519->new->generate_key;
      my $public_key = $pk->export_key_pem('public');
      my $user =
        GL::User->random(key_version => $rt->encryption_key_version)
        ->insert($rt->db, $rt->get_key);
      isnt(undef, $user->ed25519_private);

      $user->update_ed25519_public($rt->db, $rt->get_key, $public_key);
      is($public_key,             $user->ed25519_public);
      is(sha256_hex($public_key), $user->ed25519_public_digest);
      is(undef,                   $user->ed25519_private);

      my $read_user = GL::User->read($rt->db, $rt->get_key, $user->id);
      is($public_key,             $read_user->ed25519_public);
      is(sha256_hex($public_key), $read_user->ed25519_public_digest);
    },

    lives {
      my $rt         = GL::Runtime::Test->new;
      my $pk         = Crypt::PK::Ed25519->new->generate_key;
      my $public_key = $pk->export_key_pem('public');
      my $caught     = false;
      try {
        # User is never inserted, so the update doesn't change a row.
        my $user = GL::User->random(key_version => $rt->encryption_key_version)
          ->update_ed25519_public($rt->db, $rt->get_key, $public_key);
      }
      catch ($e) {
        like($e, qr/no rows affected/);
        $caught = true;
      }
      ok($caught);
    },
  ) or warn($EVAL_ERROR);

  done_testing;
};

subtest 'update status' => sub {
  ok(
    lives {
      my $rt = GL::Runtime::Test->new;
      my $user =
        GL::User->random(key_version => $rt->encryption_key_version)
        ->insert($rt->db, $rt->get_key)
        ->update_status($rt->db, $STATUS_INACTIVE);
      is($STATUS_INACTIVE, $user->status);
      is($STATUS_INACTIVE,
        GL::User->read($rt->db, $rt->get_key, $user->id)->status);
      $user->update_status($rt->db, $STATUS_ACTIVE);
      is($STATUS_ACTIVE, $user->status);
      is($STATUS_ACTIVE,
        GL::User->read($rt->db, $rt->get_key, $user->id)->status);
    },

    lives {
      my $rt     = GL::Runtime::Test->new;
      my $caught = false;
      try {
        # User is never inserted, so the update doesn't change a row.
        my $user = GL::User->random(key_version => $rt->encryption_key_version)
          ->update_status($rt->db, $STATUS_INACTIVE);
      }
      catch ($e) {
        like($e, qr/no rows affected/);
        $caught = true;
      }
      ok($caught);
    },
  ) or note($EVAL_ERROR);

  done_testing;
};

done_testing;
