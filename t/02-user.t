use v5.42;
use strictures 2;
use Crypt::Digest::SHA256   qw( sha256_hex );
use Crypt::Misc             qw( random_v4uuid );
use Crypt::PK::Ed25519      ();
use English                 qw(-no_match_vars);
use Test2::V0               qw( done_testing is isnt note ok subtest );
use Test2::Tools::Exception qw( dies lives );
use GL::User                ();

our $VERSION   = '0.01';
our $AUTHORITY = 'cpan:bclawsie';

subtest 'valid User' => sub {
  ok(
    lives {
      my $u = GL::User->random;

      is($u->display_name_digest,   sha256_hex($u->display_name));
      is($u->ed25519_public_digest, sha256_hex($u->ed25519_public));
      is($u->email_digest,          sha256_hex($u->email));

      isnt($u->ed25519_private, undef);

      $u->display_name(random_v4uuid);
      is($u->display_name_digest, sha256_hex($u->display_name));

      my $pk = Crypt::PK::Ed25519->new->generate_key;
      $u->ed25519_public($pk->export_key_pem('public'));
      is($u->ed25519_public_digest, sha256_hex($u->ed25519_public));
    },
  ) or note($EVAL_ERROR);

  ok(
    lives {
      my $pk = Crypt::PK::Ed25519->new->generate_key;
      my $u = GL::User->random(ed25519_public => $pk->export_key_pem('public'));

      is($u->ed25519_public_digest, sha256_hex($u->ed25519_public));
      is($u->ed25519_private,       undef);
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

done_testing;
