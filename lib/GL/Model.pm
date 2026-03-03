package GL::Model;
use v5.42;
use strictures 2;
use Types::Common::Numeric qw( PositiveOrZeroInt );
use Types::UUID            qw( Uuid );

use GL::Attribute qw( $STATUS_ACTIVE );
use GL::Type      qw( Role Status );

our $VERSION   = '0.0.1';
our $AUTHORITY = 'cpan:bclawsie';

use Moo::Role;
use namespace::clean;

has [qw(ctime insert_order mtime)] => (
  is  => 'rwp',
  isa => PositiveOrZeroInt,
);

has 'id' => (
  is      => 'ro',
  isa     => Uuid,
  default => Uuid->generator,
);

has 'role' => (
  is       => 'ro',
  isa      => Role,
  required => true,
);

has 'signature' => (
  is  => 'rwp',
  isa => Uuid,
);

has 'status' => (
  is      => 'rwp',
  isa     => Status,
  default => $STATUS_ACTIVE,
);

requires 'schema_version';

__END__
