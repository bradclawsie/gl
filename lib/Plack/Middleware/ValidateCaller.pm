package Plack::Middleware::ValidateCaller;
use v5.42;
use strictures 2;
use parent 'Plack::Middleware';
use Carp            qw( croak );
use Crypt::Misc     qw( is_v4uuid );
use Plack::Request  ();
use Plack::Response ();

use GL::Attribute qw( $X_GROKLOC_ID );
use GL::Org       ();
use GL::User      ();

our $VERSION   = '0.0.1';
our $AUTHORITY = 'cpan:bclawsie';

# Validate the caller and populate $env with caller User and Org.
sub call ($self, $env) {
  my $rt  = $env->{rt} || croak 'no runtime in env';
  my $req = Plack::Request->new($env);

  unless (defined $req->header($X_GROKLOC_ID)) {
    my $res = Plack::Response->new(400);
    $res->content_type('text/plain');
    $res->body("missing $X_GROKLOC_ID header");
    return $res->finalize;
  }

  my $user_id = $req->header($X_GROKLOC_ID);
  unless (is_v4uuid $user_id) {
    my $res = Plack::Response->new(400);
    $res->content_type('text/plain');
    $res->body("malformed $X_GROKLOC_ID header");
    return $res->finalize;
  }

  $env->{caller_is_root} = false;
  if ($user_id eq $rt->root->owner->id) {
    $env->{calling_org}    = $rt->root;
    $env->{calling_user}   = $rt->root->owner;
    $env->{caller_is_root} = true;
    return $self->app->($env);
  }

  my ($calling_org, $calling_user);
  try {
    $calling_user = GL::User->read($rt->db, $rt->get_key, $user_id);
  }
  catch ($e) {
    if ($e =~ qr/not found/) {
      my $res = Plack::Response->new(404);
      $res->content_type('text/plain');
      $res->body('user not found');
      return $res->finalize;
    }
  }

  try {
    $calling_org = GL::Org->read($rt->db, $rt->get_key, $calling_user->org);
  }
  catch ($e) {
    if ($e =~ qr/not found/) {
      my $m = 'org ' . $calling_user->org . " org of user $user_id not found";
      $rt->log->error($m);
      my $res = Plack::Response->new(500);
      $res->content_type('text/plain');
      $res->body('internal error');
      return $res->finalize;
    }
  }

  # check active status for user and org

  return $self->app->($env);
}

__END__
