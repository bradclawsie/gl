package GL::Org;
use v5.42;
use strictures 2;
use Carp                  qw( croak );
use Crypt::Misc           qw( random_v4uuid );
use Readonly              ();
use Time::Piece           ();
use Type::Params          qw( signature_for );
use Types::Common::String qw( NonEmptyStr );
use Types::Standard qw( ClassName CodeRef HashRef InstanceOf Slurpy Value );
use Types::UUID     qw( Uuid );

use GL::Attribute qw( $DATE $ROLE_TEST $STATUS_ACTIVE );
use GL::Type      qw( DB );
use GL::User      ();

our $VERSION   = '0.0.1';
our $AUTHORITY = 'cpan:bclawsie';

Readonly::Scalar our $SCHEMA_VERSION => 0;

use Marlin
  -modifiers,
  -with => ['GL::Model'],

  'name!' => NonEmptyStr,

  'owner!' => InstanceOf ['GL::User'];

signature_for insert => (
  method     => true,
  positional => [ DB, CodeRef ],
);

sub insert ($self, $db, $get_key) {

  $self->owner->insert($db, $get_key);

  my $query = <<~'INSERT_ORG';
    insert into org
    (id,
    name,
    owner,
    role,
    schema_version,
    status)
    values
    (?,?,?,?,?,?)
    returning ctime, insert_order, mtime, signature
    INSERT_ORG

  my $returning;
  try {
    $returning = $db->run(
      fixup => sub {
        return $_->selectrow_hashref($query, undef, $self->id, $self->name,
          $self->owner->id, $self->role, $self->schema_version, $self->status);
      }
    );
  }
  catch ($e) {
    croak $e;
  }

  $self->ctime($returning->{ctime});
  $self->insert_order($returning->{insert_order});
  $self->mtime($returning->{mtime});
  $self->signature($returning->{signature});

  return $self;
}

signature_for read => (
  method     => false,
  positional => [ ClassName, DB, CodeRef, Uuid ],
);

sub read ($class, $db, $get_key, $id) {
  my $query = 'select * from user where id = ?';
  my $row   = $db->run(
    fixup => sub {
      return $_->selectrow_hashref($query, undef, $id);
    }
  );
  croak 'not found' unless defined $row;

  # Take the uuid value from the db and hydrate the owner GL::User.
  $row->{owner} = GL::User->read($db, $get_key, $row->{owner});

  return $class->new($row);
}

signature_for TO_JSON => (
  method     => true,
  positional => [],
);

sub TO_JSON ($self) {
  return {
    id    => $self->{id},
    name  => $self->{name},
    owner => $self->{owner},
    ctime => Time::Piece->gmtime($self->{ctime})->strftime($DATE),
    mtime => Time::Piece->gmtime($self->{mtime})->strftime($DATE),
  };
}

signature_for random => (
  method     => false,
  positional => [ ClassName, Slurpy [ HashRef [Value] ] ],
);

sub random ($class, $args) {
  my $id = $args->{id} // random_v4uuid;

  return $class->new(
    id             => $id,
    name           => $args->{name} // random_v4uuid,
    owner          => GL::User->random(org => $id),
    role           => $args->{role}           // $ROLE_TEST,
    schema_version => $args->{schema_version} // $SCHEMA_VERSION,
    status         => $args->{status}         // $STATUS_ACTIVE,
  );
}

__END__
