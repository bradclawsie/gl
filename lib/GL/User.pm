package GL::User;
use v5.42;
use strictures 2;
use Carp                  qw( croak );
use Crypt::Digest::SHA256 qw( sha256_hex );
use Crypt::Misc           qw( random_v4uuid );
use Crypt::PK::Ed25519    ();
use Email::Address        ();
use Readonly              ();
use Time::Piece           ();
use Type::Params          qw( signature_for );
use Types::Common::String qw( NonEmptyStr );
use Types::Standard qw( CodeRef ClassName HashRef Maybe Slurpy StrMatch Value );
use Types::UUID     qw( Uuid );

use GL::Attribute qw( $DATE $ROLE_TEST $STATUS_ACTIVE );
use GL::Type      qw( DB Digest Ed25519Private Ed25519Public Password Status );
use GL::Crypt::AESGCM   qw( decrypt encrypt );
use GL::Crypt::IV       qw( random_iv );
use GL::Crypt::Password qw( random_password );

our $VERSION   = '0.0.1';
our $AUTHORITY = 'cpan:bclawsie';

Readonly::Scalar our $SCHEMA_VERSION => 0;

use Marlin
  -modifiers,
  -with => ['GL::Model'],

  'display_name==!' => {
  isa     => NonEmptyStr,
  trigger => sub ($self, @args) {
    return unless scalar(@args) && defined($args[0]);
    $self->{display_name_digest} = sha256_hex($args[0]);
  }
  },

  'display_name_digest' => Digest,

  # Typically this is undefined. If it is ever defined, it is
  # created for the purpose of delivering it to the caller once,
  # and then should be cleared.
  'ed25519_private' => {
  isa     => Maybe [Ed25519Private],
  clearer => true,
  },

  'ed25519_public!' => {
  isa     => Ed25519Public,
  trigger => sub ($self, @args) {
    return unless scalar(@args) && defined($args[0]);
    $self->{ed25519_public_digest} = sha256_hex($args[0]);
  }
  },

  'ed25519_public_digest' => Digest,

  'email!' => {
  isa     => StrMatch [$Email::Address::addr_spec],
  trigger => sub ($self, @args) {
    return unless scalar(@args) && defined($args[0]);
    $self->{email_digest} = sha256_hex($args[0]);
  }
  },

  'email_digest' => Digest,

  'key_version==' => Uuid,

  'org!' => Uuid,

  'password==!' => Password,
  ;

signature_for ed25519 => (
  method     => true,
  positional => [ Ed25519Public, Maybe [Ed25519Private] ],
);

# ed25519 provides for setting both the public and private
# keys. If the public key is ever changed, it is assumed
# that the caller possesses the private component, so
# any local private key held must be erased.
sub ed25519 ($self, $ed25519_public, $ed25519_private //= undef) {
  $self->{ed25519_public}        = $ed25519_public;
  $self->{ed25519_public_digest} = sha256_hex($ed25519_public);
  if (defined $ed25519_private) {
    $self->{ed25519_private} = $ed25519_private;
  }
  else {
    $self->clear_ed25519_private;
  }
}

signature_for insert => (
  method     => true,
  positional => [ DB, CodeRef ],
);

sub insert ($self, $db, $get_key) {
  croak 'key_version needed to insert' unless Uuid->check($self->key_version);

  my $query = <<~'INSERT_USER';
    insert into user
    (display_name,
    display_name_digest,
    ed25519_public,
    ed25519_public_digest,
    email,
    email_digest,
    id,
    key_version,
    org,
    password,
    role,
    schema_version,
    status)
    values
    (?,?,?,?,?,?,?,?,?,?,?,?,?)
    returning ctime, insert_order, mtime, signature
    INSERT_USER

  my $key = $get_key->($self->key_version);

  my $encrypted_ed25519_public =
    encrypt($self->ed25519_public, $key, random_iv);
  my $encrypted_display_name = encrypt($self->display_name, $key, random_iv);
  my $encrypted_email        = encrypt($self->email,        $key, random_iv);

  my $returning;
  try {
    $returning = $db->run(
      fixup => sub {
        return $_->selectrow_hashref(
          $query,                    undef,
          $encrypted_display_name,   $self->display_name_digest,
          $encrypted_ed25519_public, $self->ed25519_public_digest,
          $encrypted_email,          $self->email_digest,
          $self->id,                 $self->key_version,
          $self->org,                $self->password,
          $self->role,               $self->schema_version,
          $self->status,
        );
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

  my $key = $get_key->($row->{key_version});
  $row->{ed25519_public} = decrypt($row->{ed25519_public}, $key);
  $row->{display_name}   = decrypt($row->{display_name},   $key);
  $row->{email}          = decrypt($row->{email},          $key);

  return $class->new($row);
}

signature_for update_ed25519_public => (
  method     => true,
  positional => [ DB, CodeRef, Ed25519Public ],
);

sub update_ed25519_public ($self, $db, $get_key, $ed25519_public) {
  my $query = <<~'UPDATE_USER';
  update user 
  set ed25519_public = ?,
  ed25519_public_digest = ?
  where id = ?
  returning mtime, signature
  UPDATE_USER

  my $key = $get_key->($self->key_version);

  my $encrypted_ed25519_public = encrypt($ed25519_public, $key, random_iv);
  my $ed25519_public_digest    = sha256_hex($ed25519_public);

  my $returning;
  try {
    $returning = $db->run(
      fixup => sub {
        my $sth = $_->prepare($query);
        $sth->execute($encrypted_ed25519_public, $ed25519_public_digest,
          $self->id);
        my $updates = $sth->fetchrow_hashref;
        return $updates if $sth->rows == 1;
        return undef    if $sth->rows == 0;
        croak 'rows affected > 1';
      }
    );
  }
  catch ($e) {
    croak $e;
  }

  croak 'no rows affected' unless defined $returning;

  $self->mtime($returning->{mtime});
  $self->signature($returning->{signature});
  $self->ed25519($ed25519_public, undef);

  croak 'digest' if $ed25519_public_digest ne $self->ed25519_public_digest;

  return $self;
}

signature_for update_status => (
  method     => true,
  positional => [ DB, Status ],
);

sub update_status ($self, $db, $status) {
  my $query = <<~'UPDATE_USER';
  update user 
  set status = ?
  where id = ?
  returning mtime, signature
  UPDATE_USER

  my $returning;
  try {
    $returning = $db->run(
      fixup => sub {
        my $sth = $_->prepare($query);
        $sth->execute($status, $self->id);
        my $updates = $sth->fetchrow_hashref;
        return $updates if $sth->rows == 1;
        return undef    if $sth->rows == 0;
        croak 'rows affected > 1';
      }
    );
  }
  catch ($e) {
    croak $e;
  }

  croak 'no rows affected' unless defined $returning;

  $self->mtime($returning->{mtime});
  $self->signature($returning->{signature});
  $self->status($status);

  return $self;
}

signature_for TO_JSON => (
  method     => true,
  positional => [],
);

sub TO_JSON ($self) {
  return {
    id             => $self->{id},
    name           => $self->{display_name},
    email          => $self->{email},
    org            => $self->{org},
    ed25519_public => $self->{ed25519_public},
    ctime          => Time::Piece->gmtime($self->{ctime})->strftime($DATE),
    mtime          => Time::Piece->gmtime($self->{mtime})->strftime($DATE),
  };
}

signature_for random => (
  method     => false,
  positional => [ ClassName, Slurpy [ HashRef [Value] ] ],
);

sub random ($class, $args) {

  my $pk = Crypt::PK::Ed25519->new->generate_key;

  # Random User just gets new ed25519 key pair by default.
  return $class->new(
    display_name    => $args->{display_name} // random_v4uuid,
    ed25519_private => $pk->export_key_pem('private'),
    ed25519_public  => $pk->export_key_pem('public'),
    email           => $args->{email}          // random_v4uuid . '@local',
    id              => $args->{id}             // random_v4uuid,
    key_version     => $args->{key_version}    // random_v4uuid,
    org             => $args->{org}            // random_v4uuid,
    password        => $args->{password}       // random_password,
    role            => $args->{role}           // $ROLE_TEST,
    schema_version  => $args->{schema_version} // $SCHEMA_VERSION,
    status          => $args->{status}         // $STATUS_ACTIVE,
  );
}

__END__
