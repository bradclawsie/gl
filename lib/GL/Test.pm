package GL::Test;
use v5.42;
use strictures 2;
use Exporter        qw( import );
use Type::Params    qw( signature_for );
use Types::Standard qw( Tuple );

use GL::Org;
use GL::Type qw( Org Runtime User );
use GL::User;

our $VERSION   = '0.0.1';
our $AUTHORITY = 'cpan:bclawsie';

signature_for org_with_user => (
  method       => false,
  positional   => [Runtime],
  returns_list => Tuple [ Org, User ],
);

sub org_with_user ($rt) {
  my $org = GL::Org->random(key_version => $rt->encryption_key_version,)
    ->insert($rt->db, $rt->get_key);
  my $user = GL::User->random(
    key_version => $rt->encryption_key_version,
    org         => $org->id,
  )->insert($rt->db, $rt->get_key);
  return ($org, $user);
}

our @EXPORT_OK   = qw ( org_with_user );
our %EXPORT_TAGS = (all => [qw( org_with_user )]);

__END__
