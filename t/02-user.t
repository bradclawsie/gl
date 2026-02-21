use v5.42;
use strictures 2;
use Carp                    qw( croak );
use Crypt::Digest::SHA256   qw( sha256_hex );
use Crypt::Misc             qw( random_v4uuid );
use Crypt::PK::Ed25519      ();
use English                 qw(-no_match_vars);
use Test2::V0               qw( done_testing is isnt note ok subtest );
use Test2::Tools::Compare   qw( like );
use Test2::Tools::Exception qw( dies lives );
use Types::UUID             qw( Uuid );

use GL::Attribute       qw( $STATUS_ACTIVE $STATUS_INACTIVE );
use GL::Crypt::Key      qw( random_key );
use GL::Crypt::Password qw( random_password );
use GL::User            ();
use GL::Runtime::Test   ();

our $VERSION   = '0.01';
our $AUTHORITY = 'cpan:bclawsie';

subtest 'valid User' => sub {
  ok(
    lives {
      my $id = random_v4uuid;
      is($id, GL::User->random(id => $id)->id, 'match id');
    },
    'User lives'
  ) or note($EVAL_ERROR);

  ok(
    lives {
      my $user = GL::User->random;
      isnt(undef, $user->ed25519_private, 'ed25519 private undef');
      isnt(undef, $user->ed25519_public,  'ed25519 public undef');
      is(undef, $user->key, 'key undef');
    },
    'User keys unset lives'
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

      is(undef, $u->ed25519_private, 'ed25519 private undef');

      is($u->display_name_digest, sha256_hex($name0),
        'match display name digest');
      is($u->email_digest, sha256_hex($email0), 'match email digest');

      my $name1 = 'name1';
      $u->display_name($name1);
      is($u->display_name_digest, sha256_hex($name1),
        'match display name digest');

      is(
        $u->ed25519_public_digest,
        sha256_hex($u->ed25519_public),
        'match ed25519 public digest'
      );
    },
    'User digests lives'
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

      is($u->ed25519_private, undef,       'ed25519 private undef');
      is($u->ed25519_public,  $public_key, 'match ed25519 public');
      is(
        $u->ed25519_public_digest,
        sha256_hex($u->ed25519_public),
        'match ed25519 public digest'
      );
    },
    'User digests lives'
  ) or note($EVAL_ERROR);
};

subtest 'invalid attr mutations' => sub {
  ok(
    dies {
      GL::User->random->display_name_digest(q{});
    },
    'display name mutation dies'
  ) or note($EVAL_ERROR);

  ok(
    dies {
      GL::User->random->ed25519_public_digest(q{});
    },
    'ed25519 public digest mutation dies'
  ) or note($EVAL_ERROR);

  ok(
    dies {
      GL::User->random->email_digest(q{});
    },
    'email digest mutation dies'
  ) or note($EVAL_ERROR);

  ok(
    dies {
      GL::User->random->email(q{});
    },
    'email mutation dies'
  ) or note($EVAL_ERROR);

  ok(
    dies {
      GL::User->random->password(q{});
    },
    'password mutation dies'
  ) or note($EVAL_ERROR);
};

subtest 'insert' => sub {
  ok(
    lives {
      my $now  = time;
      my $rt   = GL::Runtime::Test->new;
      my $user = GL::User->random(key_version => $rt->encryption_key_version);
      is(undef, $user->key, 'key is undef');
      $user->insert($rt->db, $rt->get_key);
      isnt(undef, $user->key, 'key is defined');
      ok($user->ctime >= $now, 'valid ctime');
      ok($user->mtime >= $now, 'valid mtime');
      is(1, $user->insert_order, 'insert_order match');
      ok(Uuid->check($user->signature), 'signature is Uuid');
    },

    lives {
      my $caught = false;
      try {
        my $rt   = GL::Runtime::Test->new;
        my $user = GL::User->random;
        $user->insert($rt->db, $rt->get_key);
      }
      catch ($e) {
        like($e, qr/key_version needed/, 'match key_version exception');
        $caught = true;
      }
      ok($caught, 'caught key_version exception');
    },
    'insert lives'
  ) or note($EVAL_ERROR);
};

subtest 'insert conflict email' => sub {
  my $rt = GL::Runtime::Test->new;
  my $user0;

  ok(
    lives {
      $user0 = GL::User->random(key_version => $rt->encryption_key_version)
        ->insert($rt->db, $rt->get_key);

      my $caught = false;
      try {
        my $user = GL::User->random(
          email       => $user0->email,
          key_version => $rt->encryption_key_version,
          org         => $user0->org,
        )->insert($rt->db, $rt->get_key);
      }
      catch ($e) {
        like(
          $e,
          qr/UNIQUE constraint failed: user.email_digest, user.org/,
          'matched constraint exception'
        );
        $caught = true;
      }
      ok($caught, 'caught constraint exception');
    },
  ) or note($EVAL_ERROR);
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
        like(
          $e,
          qr/UNIQUE constraint failed: user.ed25519_public_digest, user.org/,
          'matched constraint exception'
        );
        $caught = true;
      }
      ok($caught, 'matched constraint exception');
    },
    'insert constraint lives'
  ) or note($EVAL_ERROR);
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
      is($user, $read_user, 'read user');
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
        GL::User->read($rt->db, $rt->get_key, random_v4uuid);
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

subtest 'reencrypt' => sub {

  # Build a custom get_key with keys that are all known.
  my $current_encryption_key_version = random_v4uuid;
  my $next_encryption_key_version    = random_v4uuid;
  my $encryption_keys                = {
    $current_encryption_key_version => random_key,
    $next_encryption_key_version    => random_key,
  };
  my $get_key = sub ($key_version) {
    return $encryption_keys->{$key_version} // croak 'bad key_version';
  };

  ok(
    lives {
      my $rt = GL::Runtime::Test->new(
        encryption_key_version => $current_encryption_key_version,
        get_key                => $get_key,
      );

      is(
        $current_encryption_key_version,
        $rt->encryption_key_version,
        'match encryption key verison'
      );

      is(
        $encryption_keys->{$current_encryption_key_version},
        $rt->get_key->($current_encryption_key_version),
        'match encryption key version'
      );

      is(
        $encryption_keys->{$rt->encryption_key_version},
        $rt->get_key->($current_encryption_key_version),
        'match encryption key version'
      );

      my $user = GL::User->random(key_version => $rt->encryption_key_version);
      $user->insert($rt->db, $rt->get_key);
      my ($old_mtime, $old_signature) = ($user->mtime, $user->signature);

      is($current_encryption_key_version,
        $user->key_version, 'match encryption key version');

      is($get_key->($current_encryption_key_version),
        $user->key, 'match encryption key');

      $user->reencrypt($rt->db, $rt->get_key, $next_encryption_key_version);

      ok($user->mtime >= $old_mtime, 'valid mtime');
      isnt($user->signature, $old_signature, 'signature is new');

      my $read_user = GL::User->read($rt->db, $rt->get_key, $user->id);
      $user->clear_ed25519_private;
      is($read_user, $user, 'read user');

      is($next_encryption_key_version, $read_user->key_version,
        'match encryption key version');

      is($get_key->($next_encryption_key_version),
        $read_user->key, 'match encryption key');
    },

    lives {
      my $rt = GL::Runtime::Test->new(
        encryption_key_version => $current_encryption_key_version,
        get_key                => $get_key,
      );
      my $caught = false;

      try {
        # User is never inserted, so the update doesn't change a row.
        my $user = GL::User->random(key_version => $rt->encryption_key_version)
          ->reencrypt($rt->db, $rt->get_key, $next_encryption_key_version);
      }
      catch ($e) {
        $caught = true;
      }
      ok($caught, 'caught reencrypt exception');
    },

    'reenryption lives'
  ) or note($EVAL_ERROR);
};

subtest 'update display name' => sub {
  ok(
    lives {
      my $rt           = GL::Runtime::Test->new;
      my $display_name = random_v4uuid;
      my $user =
        GL::User->random(key_version => $rt->encryption_key_version)
        ->insert($rt->db, $rt->get_key);
      my ($old_mtime, $old_signature) = ($user->mtime, $user->signature);

      $user->update_display_name($rt->db, $display_name);

      ok($user->mtime >= $old_mtime, 'valid mtime');
      isnt($user->signature, $old_signature, 'signature is new');
      is($display_name, $user->display_name, 'match display name');
      is(
        sha256_hex($display_name),
        $user->display_name_digest,
        'match display name digest'
      );

      my $read_user = GL::User->read($rt->db, $rt->get_key, $user->id);
      is($display_name, $read_user->display_name, 'match display name');
      is(
        sha256_hex($display_name),
        $read_user->display_name_digest,
        'match display name digest'
      );
    },

    lives {
      my $rt     = GL::Runtime::Test->new;
      my $caught = false;
      try {
        # User is never inserted, so the update doesn't change a row.
        my $user = GL::User->random(key_version => $rt->encryption_key_version)
          ->update_display_name($rt->db, random_v4uuid);
      }
      catch ($e) {
        $caught = true;
      }
      ok($caught, 'caught update display name exception');
    },
  ) or warn($EVAL_ERROR);
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
      my ($old_mtime, $old_signature) = ($user->mtime, $user->signature);
      isnt(undef, $user->ed25519_private, 'ed25519 private is undef');

      $user->update_ed25519_public($rt->db, $public_key);

      ok($user->mtime >= $old_mtime, 'valid mtime');
      isnt($user->signature, $old_signature, 'signature is new');
      is($public_key, $user->ed25519_public, 'match ed25519 public');
      is(
        sha256_hex($public_key),
        $user->ed25519_public_digest,
        'match ed25519 public digest'
      );
      is(undef, $user->ed25519_private, 'ed25519 private is undef');

      my $read_user = GL::User->read($rt->db, $rt->get_key, $user->id);
      is($public_key, $read_user->ed25519_public, 'match ed25519 public');
      is(
        sha256_hex($public_key),
        $read_user->ed25519_public_digest,
        'match ed25519 public digest'
      );
    },

    lives {
      my $rt         = GL::Runtime::Test->new;
      my $pk         = Crypt::PK::Ed25519->new->generate_key;
      my $public_key = $pk->export_key_pem('public');
      my $caught     = false;
      try {
        # User is never inserted, so the update doesn't change a row.
        my $user = GL::User->random(key_version => $rt->encryption_key_version)
          ->update_ed25519_public($rt->db, $public_key);
      }
      catch ($e) {
        $caught = true;
      }
      ok($caught, 'caught update ed25519 public exception');
    },
    'updated ed25519 public lives'
  ) or warn($EVAL_ERROR);
};

subtest 'update password' => sub {
  ok(
    lives {
      my $rt       = GL::Runtime::Test->new;
      my $password = random_password;
      my $user =
        GL::User->random(key_version => $rt->encryption_key_version)
        ->insert($rt->db, $rt->get_key)
        ->update_password($rt->db, $password);

      is($password, $user->password, 'match password');

      my $read_user = GL::User->read($rt->db, $rt->get_key, $user->id);
      is($password, $read_user->password, 'match password');
    },

    lives {
      my $rt     = GL::Runtime::Test->new;
      my $caught = false;
      try {
        # User is never inserted, so the update doesn't change a row.
        my $user = GL::User->random(key_version => $rt->encryption_key_version)
          ->update_password($rt->db, random_password);
      }
      catch ($e) {
        like($e, qr/no rows affected/);
        $caught = true;
      }
      ok($caught, 'caught update password exception');
    },
    'update password lives'
  ) or warn($EVAL_ERROR);
};

subtest 'update status' => sub {
  ok(
    lives {
      my $rt = GL::Runtime::Test->new;
      my $user =
        GL::User->random(key_version => $rt->encryption_key_version)
        ->insert($rt->db, $rt->get_key)
        ->update_status($rt->db, $STATUS_INACTIVE);

      is($STATUS_INACTIVE, $user->status, 'match status');
      is($STATUS_INACTIVE,
        GL::User->read($rt->db, $rt->get_key, $user->id)->status,
        'match status');
      $user->update_status($rt->db, $STATUS_ACTIVE);
      is($STATUS_ACTIVE, $user->status, 'match status');
      is($STATUS_ACTIVE,
        GL::User->read($rt->db, $rt->get_key, $user->id)->status,
        'match status');
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
        like($e, qr/no rows affected/, 'matched update status exception');
        $caught = true;
      }
      ok($caught, 'caught update status exception');
    },
    'update status lives'
  ) or note($EVAL_ERROR);
};

done_testing;

__END__
