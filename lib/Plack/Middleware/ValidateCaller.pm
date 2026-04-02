package Plack::Middleware::ValidateCaller;
use v5.42;
use strictures 2;
use parent 'Plack::Middleware';
use Carp           qw( croak );
use Crypt::Misc    qw( is_v4uuid );
use JSON::MaybeXS  qw( encode_json );
use Plack::Request ();

use GL::Attribute qw( $STATUS_ACTIVE $X_GROKLOC_ID );
use GL::HTTP      qw( http_err http_fatal );
use GL::LogLine   ();
use GL::Org       ();
use GL::User      ();

our $VERSION   = '0.0.1';
our $AUTHORITY = 'cpan:bclawsie';

# Validate the caller and populate $env with caller User and Org.
sub call ($self, $env) {
  my $req = Plack::Request->new($env);

  return http_err(400, "missing $X_GROKLOC_ID header")
    unless (defined $req->header($X_GROKLOC_ID));

  my $user_id = $req->header($X_GROKLOC_ID);
  return http_err(400, "malformed $X_GROKLOC_ID header")
    unless (is_v4uuid $user_id);

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
    return http_err(404, 'user not found') if ($e =~ qr/not found/);
    $rt->log->error(join q{ }, $log_prefix,
      encode_json({line => __LINE__, user => $user_id, error => $e}),
    );
    return http_fatal;
  }

  return http_err(400, 'user not active')
    if ($calling_user->status != $STATUS_ACTIVE);

  try {
    $calling_org = GL::Org->read($rt->db, $rt->get_key, $calling_user->org);
  }
  catch ($e) {
    $rt->log->error(join q{ }, $log_prefix,
      encode_json({line => __LINE__, org => $calling_user->org, error => $e}),
    );
    return http_fatal;
  }

  return http_err(400, 'org not active')
    if ($calling_org->status != $STATUS_ACTIVE);

  $env->{'psgix.calling_org'}  = $calling_org;
  $env->{'psgix.calling_user'} = $calling_user;

  return $self->app->($env);
}

__END__
