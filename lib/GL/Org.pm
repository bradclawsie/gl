package GL::Org;
use v5.42;
use strictures 2;
use Carp                  qw( croak );
use Crypt::Misc           qw( random_v4uuid );
use Readonly              ();
use Time::Piece           ();
use Type::Params          qw( signature_for );
use Types::Common::String qw( NonEmptyStr );
use Types::Standard
  qw( ArrayRef ClassName CodeRef HashRef InstanceOf Slurpy Value );
use Types::UUID qw( Uuid );

use GL::Attribute qw( $DATE $ROLE_TEST $STATUS_ACTIVE );
use GL::Type      qw( DB Org );
use GL::User      ();

our $VERSION   = '0.0.1';
our $AUTHORITY = 'cpan:bclawsie';

Readonly::Scalar our $SCHEMA_VERSION => 0;

use Marlin
  -modifiers,
  -with => ['GL::Model'],

  'name!' => NonEmptyStr,

  'owner!==' => InstanceOf ['GL::User'];

signature_for insert => (
  method     => true,
  positional => [ DB, CodeRef ],
  returns    => Org,
);

sub insert ($self, $db, $get_key) {
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
    $returning = $db->txn(
      fixup => sub {

        # Both owner and org are inserted or neither.
        $self->owner->insert($_, $get_key);
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
  returns    => Org,
);

sub read ($class, $db, $get_key, $id) {
  my $query = 'select * from org where id = ?';
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

signature_for update_owner => (
  method     => true,
  positional => [ DB, CodeRef, Uuid ],
  returns    => Org,
);

sub update_owner ($self, $db, $get_key, $owner) {
  my $status = $STATUS_ACTIVE;
  my $query  = <<~"UPDATE_ORG";
  update org
  set owner = (select id from user
               where id = ?
               and org = ?
               and status = $status)
  where id = ?
  returning mtime, signature
  UPDATE_ORG

  my $returning;
  try {
    $returning = $db->run(
      fixup => sub {
        my $sth = $_->prepare($query);
        $sth->execute($owner, $self->id, $self->id);
        my $updates = $sth->fetchrow_hashref;
        return $updates if $sth->rows == 1;
        return undef    if $sth->rows == 0;
        croak 'rows affected > 1';
      }
    );
  }
  catch ($e) {
    croak 'bad owner' if ($e =~ m/NOT\s+NULL\s+constraint\s+failed/xi);
    croak $e;
  }

  croak 'no rows affected' unless defined $returning;

  $self->mtime($returning->{mtime});
  $self->signature($returning->{signature});
  $self->owner(GL::User->read($db, $get_key, $owner));

  return $self;
}

signature_for users => (
  method     => true,
  positional => [ DB, Slurpy [ HashRef [Value] ] ],
  returns    => ArrayRef [HashRef],
);

sub users ($self, $db, $args) {
  %{$args} = ((last_insert_order => 0, limit => 10), %{$args});

  my $query = <<~'SELECT_ORG_USERS';
  select id,
  insert_order
  from user
  where org = ?
  and insert_order > ?
  order by insert_order asc
  limit ?
  SELECT_ORG_USERS

  return $db->run(
    fixup => sub {
      return $_->selectall_arrayref(
        $query, {Slice => {}},
        $self->{id}, $args->{last_insert_order},
        $args->{limit}
      );
    }
  );
}

signature_for TO_JSON => (
  method     => true,
  positional => [],
  returns    => NonEmptyStr,
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
  returns    => Org,
);

sub random ($class, $args) {
  my $id    = $args->{id} // random_v4uuid;
  my $owner = GL::User->random(org => $id);
  if (defined $args->{key_version}) {
    $owner->key_version($args->{key_version});
  }

  return $class->new(
    id             => $id,
    name           => $args->{name} // random_v4uuid,
    owner          => $owner,
    role           => $args->{role}           // $ROLE_TEST,
    schema_version => $args->{schema_version} // $SCHEMA_VERSION,
    status         => $args->{status}         // $STATUS_ACTIVE,
  );
}

__END__
