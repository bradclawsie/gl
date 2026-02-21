use v5.42;
use strictures 2;
use English                 qw(-no_match_vars);
use Test2::V0               qw( done_testing is note ok subtest );
use Test2::Tools::Compare   qw( like );
use Test2::Tools::Exception qw( lives );
use GL::Crypt::AESGCM       qw( decrypt encrypt );
use GL::Crypt::IV           qw( random_iv );
use GL::Crypt::Key          qw( random_key );

our $VERSION   = '0.01';
our $AUTHORITY = 'cpan:bclawsie';

my $iv  = random_iv;
my $key = random_key;
my $s   = 'hello';
my $encrypted;

subtest 'encrypt decrypt' => sub {
  ok(
    lives {
      $encrypted = encrypt($s, $key, $iv);
    },
    'encrypt lives'
  ) or note($EVAL_ERROR);

  my $text;

  ok(
    lives {
      $text = decrypt($encrypted, $key);
    },
    'decrypt lives'
  ) or note($EVAL_ERROR);

  is($text, $s, 'text matches');
};

subtest 'different key' => sub {
  ok(
    lives {
      $encrypted = encrypt($s, random_key, $iv);
    },
    'encrypt lives'
  ) or note($EVAL_ERROR);

  ok(
    lives {
      my $caught = false;
      try {
        decrypt($encrypted, $key);
      }
      catch ($e) {
        like($e, qr/^bad decrypt/);
        $caught = true;
      }
      ok($caught, 'caught decrypt exception');
    },
    'decrypt lives'
  ) or note($EVAL_ERROR);
};

done_testing;

__END__
