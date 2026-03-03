package GLX::Model;
use v5.42;
use strictures 2;
use Types::Common::Numeric qw( PositiveOrZeroInt );
use Types::UUID            qw( Uuid );

use GL::Attribute qw( $ROLE_TEST $STATUS_ACTIVE );
use GL::Type      qw( Role Status );

our $VERSION   = '0.0.1';
our $AUTHORITY = 'cpan:bclawsie';

use Moo::Role;
use namespace::clean;

has [qw(ctime insert_order mtime schema_version)] => (
  is       => 'rwp',
  isa      => PositiveOrZeroInt,
  required => true,
);

has 'id' => (
  is       => 'ro',
  isa      => Uuid,
  required => true,
);

has 'role' => (
  is      => 'ro',
  isa     => Role,
  default => $ROLE_TEST,
);

has 'schema_version' => (
  is  => 'rwp',
  isa => Uuid,
);

has 'status' => (
  is      => 'rwp',
  isa     => Status,
  default => $STATUS_ACTIVE,
);

__END__
