use v5.42;
use strictures 2;
use English                 qw(-no_match_vars);
use Test2::V0               qw( done_testing is isnt note ok subtest );
use Test2::Tools::Exception qw( lives );
use GL::Crypt::Password     qw( text_to_password verify_password );

our $VERSION   = '0.01';
our $AUTHORITY = 'cpan:bclawsie';

my $password;
my $text = 'secret';

subtest 'password' => sub {
  ok(
    lives {
      $password = text_to_password($text);
    },
    'text to password lives'
  ) or note($EVAL_ERROR);

  is(verify_password($password, $text), true, 'match password');
  isnt(verify_password($password, 'guess'), true, 'mismatch password');
};

done_testing;

__END__
