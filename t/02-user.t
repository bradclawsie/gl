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

use GL::User          ();
use GL::Runtime::Test ();

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
      my $pk         = Crypt::PK::Ed25519->new->generate_key;
      my $public_key = $pk->export_key_pem('public');
      $u->ed25519_public($public_key);
      is(undef, $u->ed25519_private);
    },
  ) or note($EVAL_ERROR);

  ok(
    lives {
      my $name0  = 'name0';
      my $email0 = 'email0';

      my $u = GL::User->new(
        display_name => $name0,
        email        => $email0,
        org          => random_v4uuid,
      );

      is($u->display_name_digest, sha256_hex($name0));
      is($u->email_digest,        sha256_hex($email0));

      my $name1 = 'name1';
      $u->display_name($name1);
      is($u->display_name_digest, sha256_hex($name1));

      isnt($u->ed25519_private, undef);
      is($u->ed25519_public_digest, sha256_hex($u->ed25519_public));

      my $pk         = Crypt::PK::Ed25519->new->generate_key;
      my $public_key = $pk->export_key_pem('public');
      $u->ed25519_public($public_key);

      # Setting ed25519_public undefs the ed25519_private.
      is($u->ed25519_private,       undef);
      is($u->ed25519_public,        $public_key);
      is($u->ed25519_public_digest, sha256_hex($u->ed25519_public));
    },
  ) or note($EVAL_ERROR);

  ok(
    lives {
      my $name0      = 'name0';
      my $email0     = 'email0';
      my $pk         = Crypt::PK::Ed25519->new->generate_key;
      my $public_key = $pk->export_key_pem('public');

      my $u = GL::User->new(
        display_name   => $name0,
        email          => $email0,
        org            => random_v4uuid,
        ed25519_public => $public_key,
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

done_testing;
