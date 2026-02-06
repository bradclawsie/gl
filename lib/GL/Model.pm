package GL::Model;
use v5.42;
use strictures 2;
use Types::Common::Numeric qw( PositiveOrZeroInt );
use Types::UUID            qw( Uuid );
use GL::Attribute          qw( $ROLE_TEST $STATUS_ACTIVE );
use GL::Type               qw( Role Status );

our $VERSION   = '0.0.1';
our $AUTHORITY = 'cpan:bclawsie';

use Marlin::Role
  'ctime==' => PositiveOrZeroInt,

  'id!' => {
  isa     => Uuid,
  default => Uuid->generator,
  },

  'insert_order==' => PositiveOrZeroInt,

  'mtime==' => PositiveOrZeroInt,

  'role!' => {
  isa     => Role,
  default => $ROLE_TEST,
  },

  'schema_version' => PositiveOrZeroInt,

  'signature==' => Uuid,

  'status==!' => {
  isa     => Status,
  default => $STATUS_ACTIVE,
  };
