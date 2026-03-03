package GL::User;
use v5.42;
use strictures 2;
use Carp                   qw( croak );
use Crypt::Misc            qw( random_v4uuid );
use Crypt::PK::Ed25519     ();
use Email::Address         ();
use Readonly               ();
use Time::Piece            ();
use Type::Params           qw( signature_for );
use Types::Common::Numeric qw( PositiveOrZeroInt );
use Types::Common::String  qw( NonEmptyStr );
use Types::Standard qw( CodeRef ClassName HashRef Maybe Slurpy StrMatch Value );
use Types::UUID     qw( Uuid );

use GL::Attribute qw( $DATE $ROLE_TEST $STATUS_ACTIVE );
use GL::Type      qw(
  DB
  DBH
  Digest
  Ed25519Private
  Ed25519Public
  Password
  Status
  User
);
use GL::Crypt::AESGCM   qw( decrypt encrypt );
use GL::Crypt::IV       qw( random_iv );
use GL::Crypt::Password qw( random_password );

our $VERSION   = '0.0.1';
our $AUTHORITY = 'cpan:bclawsie';

Readonly::Scalar our $SCHEMA_VERSION => 0;

use Moo;

has 'display_name' => (
  is       => 'rwp',
  isa      => NonEmptyStr,
  required => true,
);

# Digests are only set on an insert or update.
has [qw(display_name_digest email_digest ed25519_public_digest)] => (
  is  => 'rwp',
  isa => Digest,
);

has 'ed25519_private' => (
  is      => 'rwp',
  isa     => Maybe [Ed25519Private],
  clearer => true,
);

has 'ed25519_public' => (
  is       => 'rwp',
  isa      => Ed25519Public,
  required => true,
);

has 'email' => (
  is       => 'ro',
  isa      => StrMatch [$Email::Address::addr_spec],
  required => true,
);

has 'encryption_key_version' => (
  is       => 'rwp',
  isa      => Uuid,
  required => true,
);

has 'org' => (
  is       => 'ro',
  isa      => Uuid,
  required => true,
);

has 'password' => (
  is       => 'rwp',
  isa      => Password,
  required => true,
);

has 'schema_version' => (
  is      => 'rwp',
  isa     => PositiveOrZeroInt,
  default => $SCHEMA_VERSION,
);

with 'GL::Model';

# _ed25519 provides for setting both the public and private
# keys. If the public key is ever changed, it is assumed
# that the caller possesses the private component, so
# any local private key held must be erased.
sub _ed25519 ($self, $ed25519_public, $ed25519_private //= undef) {
  $self->_set_ed25519_public($ed25519_public);
  if (defined $ed25519_private) {
    $self->_set_ed25519_private($ed25519_private);
  }
  else {
    $self->clear_ed25519_private;
  }
  return $self;
}

signature_for insert => (
  method     => true,
  positional => [ DB, CodeRef, CodeRef ],
  returns    => User,
);

sub insert ($self, $db, $get_key, $hmac) {
  return $db->run(
    fixup => sub ($dbh) {
      return $self->insert_query($dbh, $get_key, $hmac);
    }
  );
}

signature_for insert_query => (
  method     => true,
  positional => [ DBH, CodeRef, CodeRef ],
  returns    => User,
);

sub insert_query ($self, $dbh, $get_key, $hmac) {
  my $query = <<~'INSERT_USER';
    insert into user
    (display_name,
    display_name_digest,
    ed25519_public,
    ed25519_public_digest,
    email,
    email_digest,
    encryption_key_version,
    id,
    org,
    password,
    role,
    schema_version,
    status)
    values
    (?,?,?,?,?,?,?,?,?,?,?,?,?)
    returning ctime, insert_order, mtime, signature
    INSERT_USER

  my $display_name_digest   = $hmac->($self->display_name);
  my $ed25519_public_digest = $hmac->($self->ed25519_public);
  my $email_digest          = $hmac->($self->email);

  my $key                    = $get_key->($self->encryption_key_version);
  my $encrypted_display_name = encrypt($self->display_name, $key, random_iv);
  my $encrypted_ed25519_public =
    encrypt($self->ed25519_public, $key, random_iv);
  my $encrypted_email = encrypt($self->email, $key, random_iv);

  my $returning = $dbh->selectrow_hashref(
    $query,                        undef,
    $encrypted_display_name,       $display_name_digest,
    $encrypted_ed25519_public,     $ed25519_public_digest,
    $encrypted_email,              $email_digest,
    $self->encryption_key_version, $self->id,
    $self->org,                    $self->password,
    $self->role,                   $self->schema_version,
    $self->status,
  );

  $self->_set_display_name_digest($display_name_digest);
  $self->_set_ed25519_public_digest($ed25519_public_digest);
  $self->_set_email_digest($email_digest);
  $self->_set_ctime($returning->{ctime});
  $self->_set_insert_order($returning->{insert_order});
  $self->_set_mtime($returning->{mtime});
  $self->_set_signature($returning->{signature});

  return $self;
}

signature_for read => (
  method     => false,
  positional => [ ClassName, DB, CodeRef, Uuid ],
  returns    => User,
);

sub read ($class, $db, $get_key, $id) {
  return $db->run(
    fixup => sub ($dbh) {
      return $class->read_query($dbh, $get_key, $id);
    }
  );
}

signature_for read_query => (
  method     => false,
  positional => [ ClassName, DBH, CodeRef, Uuid ],
  returns    => User,
);

sub read_query ($class, $dbh, $get_key, $id) {
  my $query = 'select * from user where id = ?';
  my $row   = $dbh->selectrow_hashref($query, undef, $id);
  croak 'not found' unless defined $row;

  my $key = $get_key->($row->{encryption_key_version});
  $row->{ed25519_public} = decrypt($row->{ed25519_public}, $key);
  $row->{display_name}   = decrypt($row->{display_name},   $key);
  $row->{email}          = decrypt($row->{email},          $key);

  return $class->new($row);
}

signature_for reencrypt => (
  method     => true,
  positional => [ DB, CodeRef, Uuid ],
  returns    => User,
);

sub reencrypt ($self, $db, $get_key, $encryption_key_version) {
  return $db->run(
    fixup => sub ($dbh) {
      return $self->reencrypt_query($dbh, $get_key, $encryption_key_version);
    }
  );
}

signature_for reencrypt_query => (
  method     => true,
  positional => [ DBH, CodeRef, Uuid ],
  returns    => User,
);

sub reencrypt_query ($self, $dbh, $get_key, $encryption_key_version) {
  my $key = $get_key->($encryption_key_version);

  my $query = <<~'UPDATE_USER';
  update user set
  display_name = ?,
  ed25519_public = ?,
  email = ?,
  encryption_key_version = ?
  where id = ?
  returning mtime, signature
  UPDATE_USER

  my $encrypted_display_name = encrypt($self->display_name, $key, random_iv);
  my $encrypted_ed25519_public =
    encrypt($self->ed25519_public, $key, random_iv);
  my $encrypted_email = encrypt($self->email, $key, random_iv);

  my $sth = $dbh->prepare($query);
  $sth->execute($encrypted_display_name, $encrypted_ed25519_public,
    $encrypted_email, $encryption_key_version, $self->id);
  my $returning = $sth->fetchrow_hashref;
  croak 'no rows affected'  if $sth->rows == 0;
  croak 'rows affected > 1' if $sth->rows != 1;

  $self->_set_mtime($returning->{mtime});
  $self->_set_signature($returning->{signature});
  $self->_set_encryption_key_version($encryption_key_version);

  return $self;
}

signature_for update_display_name => (
  method     => true,
  positional => [ DB, CodeRef, CodeRef, NonEmptyStr ],
  returns    => User,
);

sub update_display_name ($self, $db, $get_key, $hmac, $display_name) {
  return $db->run(
    fixup => sub ($dbh) {
      return $self->update_display_name_query($dbh, $get_key, $hmac,
        $display_name);
    }
  );
}

signature_for update_display_name_query => (
  method     => true,
  positional => [ DBH, CodeRef, CodeRef, NonEmptyStr ],
  returns    => User,
);

sub update_display_name_query ($self, $dbh, $get_key, $hmac, $display_name) {
  my $key = $get_key->($self->encryption_key_version);

  my $query = <<~'UPDATE_USER';
  update user 
  set display_name = ?,
  display_name_digest = ?
  where id = ?
  returning mtime, signature
  UPDATE_USER

  my $encrypted_display_name = encrypt($display_name, $key, random_iv);
  my $display_name_digest    = $hmac->($display_name);

  my $sth = $dbh->prepare($query);
  $sth->execute($encrypted_display_name, $display_name_digest, $self->id);
  my $returning = $sth->fetchrow_hashref;
  croak 'no rows affected'  if $sth->rows == 0;
  croak 'rows affected > 1' if $sth->rows != 1;

  $self->_set_mtime($returning->{mtime});
  $self->_set_signature($returning->{signature});
  $self->_set_display_name($display_name);
  $self->_set_display_name_digest($display_name_digest);

  return $self;
}

signature_for update_ed25519_public => (
  method     => true,
  positional => [ DB, CodeRef, CodeRef, Ed25519Public ],
  returns    => User,
);

sub update_ed25519_public ($self, $db, $get_key, $hmac, $ed25519_public) {
  return $db->run(
    fixup => sub ($dbh) {
      return $self->update_ed25519_public_query($dbh, $get_key, $hmac,
        $ed25519_public);
    }
  );
}

signature_for update_ed25519_public_query => (
  method     => true,
  positional => [ DBH, CodeRef, CodeRef, Ed25519Public ],
  returns    => User,
);

sub update_ed25519_public_query ($self, $dbh, $get_key, $hmac, $ed25519_public) {
  my $key = $get_key->($self->encryption_key_version);

  my $query = <<~'UPDATE_USER';
  update user 
  set ed25519_public = ?,
  ed25519_public_digest = ?
  where id = ?
  returning mtime, signature
  UPDATE_USER

  my $encrypted_ed25519_public = encrypt($ed25519_public, $key, random_iv);
  my $ed25519_public_digest    = $hmac->($ed25519_public);

  my $sth = $dbh->prepare($query);
  $sth->execute($encrypted_ed25519_public, $ed25519_public_digest, $self->id);
  my $returning = $sth->fetchrow_hashref;
  croak 'no rows affected'  if $sth->rows == 0;
  croak 'rows affected > 1' if $sth->rows != 1;

  $self->_set_mtime($returning->{mtime});
  $self->_set_signature($returning->{signature});
  $self->_ed25519($ed25519_public);
  $self->_set_ed25519_public_digest($ed25519_public_digest);

  return $self;
}

signature_for update_password => (
  method     => true,
  positional => [ DB, Password ],
  returns    => User,
);

sub update_password ($self, $db, $password) {
  return $db->run(
    fixup => sub ($dbh) {
      return $self->update_password_query($dbh, $password);
    }
  );
}

signature_for update_password_query => (
  method     => true,
  positional => [ DBH, Password ],
  returns    => User,
);

sub update_password_query ($self, $dbh, $password) {
  my $query = <<~'UPDATE_USER';
  update user 
  set password = ?
  where id = ?
  returning mtime, signature
  UPDATE_USER

  my $sth = $dbh->prepare($query);
  $sth->execute($password, $self->id);
  my $returning = $sth->fetchrow_hashref;
  croak 'no rows affected'  if $sth->rows == 0;
  croak 'rows affected > 1' if $sth->rows != 1;

  $self->_set_mtime($returning->{mtime});
  $self->_set_signature($returning->{signature});
  $self->_set_password($password);

  return $self;
}

signature_for update_status => (
  method     => true,
  positional => [ DB, Status ],
  returns    => User,
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
  returns    => User,
);

sub update_status_query ($self, $dbh, $status) {
  my $query = <<~'UPDATE_USER';
  update user 
  set status = ?
  where id = ?
  returning mtime, signature
  UPDATE_USER

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

signature_for TO_JSON => (
  method     => true,
  positional => [],
  returns    => HashRef,
);

sub TO_JSON ($self) {
  return {
    id             => $self->id,
    display_name   => $self->display_name,
    email          => $self->email,
    org            => $self->org,
    ed25519_public => $self->ed25519_public,
    ctime          => Time::Piece->gmtime($self->ctime)->strftime($DATE),
    mtime          => Time::Piece->gmtime($self->mtime)->strftime($DATE),
  };
}

signature_for random => (
  method     => false,
  positional => [ ClassName, Slurpy [ HashRef [Value] ] ],
  returns    => User,
);

# Note that any User generated with this must reference
# a DB-valid org in order to satisfy the FK constaints.
sub random ($class, $args) {

  my $pk = Crypt::PK::Ed25519->new->generate_key;

  return $class->new(
    display_name           => $args->{display_name} // random_v4uuid,
    ed25519_private        => $pk->export_key_pem('private'),
    ed25519_public         => $pk->export_key_pem('public'),
    encryption_key_version => $args->{encryption_key_version} // random_v4uuid,
    email          => $args->{email}          // random_v4uuid . '@local',
    id             => $args->{id}             // random_v4uuid,
    org            => $args->{org}            // random_v4uuid,
    password       => $args->{password}       // random_password,
    role           => $args->{role}           // $ROLE_TEST,
    schema_version => $args->{schema_version} // $SCHEMA_VERSION,
    status         => $args->{status}         // $STATUS_ACTIVE,
  );
}

__END__
