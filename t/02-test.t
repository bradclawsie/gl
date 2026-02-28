use v5.42;
use strictures 2;
use English                 qw(-no_match_vars);
use Test2::V0               qw( done_testing is note ok subtest );
use Test2::Tools::Exception qw( lives );

use GL::Org           ();
use GL::Test          qw( org_with_user );
use GL::User          ();
use GL::Runtime::Test ();

our $VERSION   = '0.01';
our $AUTHORITY = 'cpan:bclawsie';

subtest 'org with user' => sub {
  ok(
    lives {
      my $rt = GL::Runtime::Test->new;
      my ($org, $user) = org_with_user($rt);
      $org->owner->clear_ed25519_private;
      $user->clear_ed25519_private;
      my $read_org  = GL::Org->read($rt->db, $rt->get_key, $org->id);
      my $read_user = GL::User->read($rt->db, $rt->get_key, $user->id);
      is($read_org,  $org,  'read org');
      is($read_user, $user, 'read user');
    },
  ) or note($EVAL_ERROR);
};

done_testing;

__END__
