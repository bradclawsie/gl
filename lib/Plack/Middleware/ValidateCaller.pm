package Plack::Middleware::ValidateCaller;
use v5.42;
use strictures 2;
use parent 'Plack::Middleware';
use Carp            qw( croak );
use Crypt::Misc     qw( is_v4uuid );
use JSON::MaybeXS   qw( encode_json );
use Plack::Request  ();
use Plack::Response ();

use GL::Attribute qw( $STATUS_ACTIVE $X_GROKLOC_ID );
use GL::LogLine   ();
use GL::Org       ();
use GL::User      ();

our $VERSION   = '0.0.1';
our $AUTHORITY = 'cpan:bclawsie';

# Validate the caller and populate $env with caller User and Org.
sub call ($self, $env) {
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

  my $rt = $env->{'psgix.runtime'} || croak 'enable WithRuntime';

  my $log_prefix = GL::LogLine->prefix($env);

  $rt->log->info(join(q{ }, $log_prefix, encode_json({user => $user_id})));

  $env->{'psgix.caller_is_root'} = false;
  if ($user_id eq $rt->root->owner->id) {
    $env->{'psgix.calling_org'}    = $rt->root;
    $env->{'psgix.calling_user'}   = $rt->root->owner;
    $env->{'psgix.caller_is_root'} = true;
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
    else {
      $rt->log->error(join q{ }, $log_prefix,
        encode_json({line => __LINE__, user => $user_id, error => $e}),
      );
      my $res = Plack::Response->new(500);
      $res->content_type('text/plain');
      $res->body('internal error');
      return $res->finalize;
    }
  }

  # check active status for user
  if ($calling_user->status != $STATUS_ACTIVE) {
    my $res = Plack::Response->new(400);
    $res->content_type('text/plain');
    $res->body('user not active');
    return $res->finalize;
  }

  try {
    $calling_org = GL::Org->read($rt->db, $rt->get_key, $calling_user->org);
  }
  catch ($e) {
    $rt->log->error(join q{ }, $log_prefix,
      encode_json({line => __LINE__, org => $calling_user->org, error => $e}),
    );
    my $res = Plack::Response->new(500);
    $res->content_type('text/plain');
    $res->body('internal error');
    return $res->finalize;
  }

  # check active status for org
  if ($calling_org->status != $STATUS_ACTIVE) {
    my $res = Plack::Response->new(400);
    $res->content_type('text/plain');
    $res->body('org not active');
    return $res->finalize;
  }

  $env->{'psgix.calling_org'}  = $calling_org;
  $env->{'psgix.calling_user'} = $calling_user;

  return $self->app->($env);
}

__END__
