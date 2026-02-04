package GL::Model;
use v5.42;
use strictures 2;
use Types::Common::Numeric qw( PositiveOrZeroInt );
use Types::UUID            qw( Uuid );
use GL::Attribute          qw( $ROLE_NORMAL $STATUS_UNCONFIRMED );
use GL::Type               qw( Role Status );

our $VERSION   = '0.0.1';
our $AUTHORITY = 'cpan:bclawsie';

use Marlin::Role
  'ctime==' => {
  isa     => PositiveOrZeroInt->where('$_ == 0 || $_ > 1768753518'),
  default => 0,
  },

  'id!' => {
  isa     => Uuid,
  coerce  => true,
  default => Uuid->generator,
  },

  'insert_order==' => {isa => PositiveOrZeroInt},

  'mtime==' => {
  isa     => PositiveOrZeroInt->where('$_ == 0 || $_ > 1768753518'),
  default => 0,
  },

  'role!' => {
  isa     => Role,
  default => $ROLE_NORMAL,
  },

  'signature==' => {
  isa    => Uuid,
  coerce => true,
  },

  'status==!' => {
  isa     => Status,
  default => $STATUS_UNCONFIRMED,
  };
