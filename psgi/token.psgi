# vim: set filetype=perl :
use v5.42;
use strictures 2;
use Carp               qw( croak );
use Crypt::Misc        qw( random_v4uuid );
use Crypt::PK::Ed25519 ();
use JSON::MaybeXS      qw( encode_json );
use Plack::Builder     qw( builder mount );
use Plack::Request     ();
use Plack::Response    ();

use GL::Crypt::JWT ();

our $VERSION   = '0.0.1';
our $AUTHORITY = 'cpan:bclawsie';

my $post_handler = sub ($env) {
  my $rt  = $env->{rt} || croak 'no runtime in env';
  my $req = Plack::Request->new($env);

  if ($req->method ne 'POST') {
    my $res = Plack::Response->new(405);
    $res->content_type('text/plain');
    $res->body(q{method must be POST});
    return $res->finalize;
  }

  unless (defined $env->{'psgix.request_id'}) {
    croak 'RequestId middleware must be enabled';
  }

  unless (defined $env->{'psgix.payload'}) {
    croak 'RequireJSON middleware must be enabled';
  }

  my $calling_user = $env->{'psgix.calling_user'} || croak 'calling_user';

  my $log_prefix = join(q{ },
    q{[} . $env->{'psgix.request_id'} . q{]},
    q{[} . $req->path_info . q{]});

  $rt->log->info(
    join(q{ }, $log_prefix, encode_json({user => $calling_user->id})));

  my $payload = $env->{'psgix.payload'};

  unless (defined $payload->{proof}) {
    my $res = Plack::Response->new(400);
    $res->content_type('text/plain');
    $res->body(q{'proof' must be set in payload});
    return $res->finalize;
  }

  my $pub = Crypt::PK::Ed25519->new(\$calling_user->ed25519_public);
  unless (
    $pub->verify_message(pack('H*', $payload->{proof}), $calling_user->id))
  {
    my $res = Plack::Response->new(401);
    $res->content_type('text/plain');
    $res->body(q{authentication proof not verified});
    return $res->finalize;
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
  mount q{/} => $post_handler;
};

__END__
