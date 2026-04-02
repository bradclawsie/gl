# vim: set filetype=perl :
use v5.42;
use strictures 2;
use Carp               qw( croak );
use Crypt::Misc        qw( random_v4uuid );
use Crypt::PK::Ed25519 ();
use JSON::MaybeXS      qw( encode_json );
use Plack::Builder     qw( builder enable );
use Plack::Request     ();

use GL::Crypt::JWT ();
use GL::HTTP       qw( http_err );
use GL::LogLine    ();

our $VERSION   = '0.0.1';
our $AUTHORITY = 'cpan:bclawsie';

my $post_handler = sub ($env) {
  my $req = Plack::Request->new($env);

  return http_err(405, q{method must be POST}) if ($req->method ne 'POST');

  my $request_id   = $env->{'psgix.request_id'} || croak 'enable RequestId';
  my $rt           = $env->{'psgix.runtime'}    || croak 'enable WithRuntime';
  my $calling_user = $env->{'psgix.calling_user'}
    || croak 'enable ValidateCaller';
  my $log_prefix = GL::LogLine->prefix($env);

  $rt->log->info(
    join(q{ }, $log_prefix, encode_json({user => $calling_user->id})));

  my $payload = $env->{'psgix.payload'} || croak 'enable RequireJSON';

  return http_err(400, q{'proof' must be set in payload})
    unless (defined $payload->{proof});

  my $pub = Crypt::PK::Ed25519->new(\$calling_user->ed25519_public);
  unless (
    $pub->verify_message(pack('H*', $payload->{proof}), $calling_user->id))
  {
    return http_err(401, q{authentication proof not verified});
  }

  my $now = time;
  my $jwt = GL::Crypt::JWT->new(
    exp => $now + 86_400,
    id  => random_v4uuid,
    iss => 'GrokLOC.com',
    nbf => $now - 1,
    sub => $calling_user->id,
  );
  my $token = $jwt->encode($rt->token_key);

  my $res = $req->new_response(200);
  $res->content_type('application/json');
  $res->body(encode_json({token => $token}));
  return $res->finalize;
};

builder {
  enable 'ValidateCaller';
  enable 'RequireJSON';

  $post_handler;
};

__END__
