package GL::Model::Base;
use v5.42;
use strictures 2;
use Types::Common::Numeric qw( PositiveOrZeroInt );
use Types::UUID            qw( Uuid );
use GL::Attribute          qw( $ROLE_NORMAL $STATUS_UNCONFIRMED );
use GL::Type               qw( Role Status );

use Moo::Role;

our $VERSION   = '0.0.1';
our $AUTHORITY = 'cpan:bclawsie';

has [qw( ctime mtime )] => (
  is       => 'rw',
  isa      => PositiveOrZeroInt->where('$_ == 0 || $_ > 1768753518'),
  required => false,       # db populated on insert/update
  default  => sub { 0 },
);

has id => (
  is       => 'ro',
  isa      => Uuid,
  required => true,
  coerce   => 1,
  default  => Uuid->generator,
);

has insert_order => (
  is       => 'rw',
  isa      => PositiveOrZeroInt,
  required => false,               # db populated on insert
  default  => sub { 0 },
);

has role => (
  is       => 'ro',
  isa      => Role,
  required => false,
  default  => sub { $ROLE_NORMAL },
);

has schema_version => (
  is       => 'ro',
  isa      => PositiveOrZeroInt,
  required => false,
  default  => sub { 0 },
);

has signature => (
  is       => 'rw',
  isa      => Uuid,
  required => false,             # db populated on insert/update
  coerce   => 1,
  default  => Uuid->generator,
);

has status => (
  is       => 'rw',
  isa      => Status,
  required => false,
  default  => sub { $STATUS_UNCONFIRMED },
);

__END__
