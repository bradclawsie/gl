package GL::Org;
use v5.42;
use strictures 2;
use Carp                   qw( croak );
use Crypt::Misc            qw( random_v4uuid );
use Readonly               ();
use Time::Piece            ();
use Type::Params           qw( signature_for );
use Types::Common::Numeric qw( PositiveOrZeroInt );
use Types::Common::String  qw( NonEmptyStr );
use Types::Standard qw( ArrayRef ClassName CodeRef HashRef Slurpy Value );
use Types::UUID     qw( Uuid );

use GL::Attribute qw( $DATE $ROLE_TEST $STATUS_ACTIVE );
use GL::Type      qw( DB DBH Org Status User );
use GL::User      ();

our $VERSION   = '0.0.1';
our $AUTHORITY = 'cpan:bclawsie';

Readonly::Scalar our $SCHEMA_VERSION => 0;

use Moo;

has 'name' => (
  is       => 'ro',
  isa      => NonEmptyStr,
  required => true,
);

has 'owner' => (
  is       => 'rwp',
  isa      => User,
  required => true,
);

has 'schema_version' => (
  is      => 'rwp',
  isa     => PositiveOrZeroInt,
  default => $SCHEMA_VERSION,
);

with 'GL::Model';

signature_for insert => (
  method     => true,
  positional => [ DB, CodeRef, CodeRef ],
  returns    => Org,
);

sub insert ($self, $db, $get_key, $hmac) {
  return $db->txn(
    fixup => sub ($dbh) {
      return $self->insert_query($dbh, $get_key, $hmac);
    }
  );
}

signature_for insert_query => (
  method     => true,
  positional => [ DBH, CodeRef, CodeRef ],
  returns    => Org,
);

# insert_query inserts the org and the owner User.
sub insert_query ($self, $dbh, $get_key, $hmac) {
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

  $self->owner->insert_query($dbh, $get_key, $hmac);
  my $returning = $dbh->selectrow_hashref($query, undef, $self->id, $self->name,
    $self->owner->id, $self->role, $self->schema_version, $self->status);

  $self->_set_ctime($returning->{ctime});
  $self->_set_insert_order($returning->{insert_order});
  $self->_set_mtime($returning->{mtime});
  $self->_set_signature($returning->{signature});

  return $self;
}

signature_for read => (
  method     => false,
  positional => [ ClassName, DB, CodeRef, Uuid ],
  returns    => Org,
);

sub read ($class, $db, $get_key, $id) {
  return $db->txn(
    fixup => sub ($dbh) {
      return $class->read_query($dbh, $get_key, $id);
    }
  );
}

signature_for read_query => (
  method     => false,
  positional => [ ClassName, DBH, CodeRef, Uuid ],
  returns    => Org,
);

sub read_query ($class, $dbh, $get_key, $id) {
  my $query = 'select * from org where id = ?';
  my $row   = $dbh->selectrow_hashref($query, undef, $id);
  croak 'not found' unless defined $row;

  # Take the uuid value from the db and hydrate the owner GL::User.
  $row->{owner} = GL::User->read_query($dbh, $get_key, $row->{owner});

  return $class->new($row);
}

signature_for update_owner => (
  method     => true,
  positional => [ DB, CodeRef, Uuid ],
  returns    => Org,
);

sub update_owner ($self, $db, $get_key, $owner) {
  return $db->txn(
    fixup => sub ($dbh) {
      return $self->update_owner_query($dbh, $get_key, $owner);
    }
  );
}

signature_for update_owner_query => (
  method     => true,
  positional => [ DBH, CodeRef, Uuid ],
  returns    => Org,
);

sub update_owner_query ($self, $dbh, $get_key, $owner) {
  my $status = $STATUS_ACTIVE;
  my $query  = <<~'UPDATE_ORG';
  update org
  set owner = (select id from user
               where id = ?
               and org = ?
               and status = ?)
  where id = ?
  returning mtime, signature
  UPDATE_ORG

  my $returning;
  try {
    my $sth = $dbh->prepare($query);
    $sth->execute($owner, $self->id, $status, $self->id);
    $returning = $sth->fetchrow_hashref;
    croak 'no rows affected'  if $sth->rows == 0;
    croak 'rows affected > 1' if $sth->rows != 1;
  }
  catch ($e) {
    croak 'bad owner' if ($e =~ m/NOT\s+NULL\s+constraint\s+failed/xi);
    croak $e;
  }

  $self->_set_mtime($returning->{mtime});
  $self->_set_signature($returning->{signature});
  $self->_set_owner(GL::User->read_query($dbh, $get_key, $owner));

  return $self;
}

signature_for update_status => (
  method     => true,
  positional => [ DB, Status ],
  returns    => Org,
);

sub update_status ($self, $db, $status) {
  return $db->run(
    fixup => sub ($dbh) {
      return $self->update_status_query($dbh, $status);
    }
  );
}

signature_for update_status_query => (
  method     => true,
  positional => [ DBH, Status ],
  returns    => Org,
);

sub update_status_query ($self, $dbh, $status) {
  my $query = <<~'UPDATE_ORG';
  update org 
  set status = ?
  where id = ?
  returning mtime, signature
  UPDATE_ORG

  my $sth = $dbh->prepare($query);
  $sth->execute($status, $self->id);
  my $returning = $sth->fetchrow_hashref;
  croak 'no rows affected'  if $sth->rows == 0;
  croak 'rows affected > 1' if $sth->rows != 1;

  $self->_set_mtime($returning->{mtime});
  $self->_set_signature($returning->{signature});
  $self->_set_status($status);

  return $self;
}

signature_for users => (
  method     => true,
  positional => [ DB, Slurpy [ HashRef [Value] ] ],
  returns    => ArrayRef [HashRef],
);

sub users ($self, $db, $args) {
  return $db->run(
    fixup => sub ($dbh) {
      return $self->users_query($dbh, $args);
    }
  );
}

signature_for users_query => (
  method     => true,
  positional => [ DBH, Slurpy [ HashRef [Value] ] ],
  returns    => ArrayRef [HashRef],
);

sub users_query ($self, $dbh, $args) {
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

  return $dbh->selectall_arrayref(
    $query, {Slice => {}},
    $self->id, $args->{last_insert_order},
    $args->{limit}
  );
}

signature_for TO_JSON => (
  method     => true,
  positional => [],
  returns    => HashRef,
);

sub TO_JSON ($self) {
  return {
    id    => $self->id,
    name  => $self->name,
    owner => $self->owner,
    ctime => Time::Piece->gmtime($self->ctime)->strftime($DATE),
    mtime => Time::Piece->gmtime($self->mtime)->strftime($DATE),
  };
}

signature_for random => (
  method     => false,
  positional => [ ClassName, Slurpy [ HashRef [Value] ] ],
  returns    => Org,
);

sub random ($class, $args) {
  my $id                     = $args->{id}                     // random_v4uuid;
  my $encryption_key_version = $args->{encryption_key_version} // random_v4uuid;
  my $owner                  = GL::User->random(
    encryption_key_version => $encryption_key_version,
    org                    => $id,
  );

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
