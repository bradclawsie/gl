# vim: set filetype=perl :
use v5.42;
use strictures 2;
use JSON::MaybeXS   qw( decode_json encode_json );
use Plack::Builder  qw( builder mount );
use Plack::Request  ();
use Plack::Response ();

our $VERSION   = '0.0.1';
our $AUTHORITY = 'cpan:bclawsie';

my $post_handler = sub ($env) {
  my $req = Plack::Request->new($env);

  if ($req->method ne 'POST') {
    my $res = Plack::Response->new(405);
    $res->content_type('text/plain');
    $res->body(qw{method must be POST});
    return $res->finalize;
  }

  my $payload = decode_json($req->content // '{}');
  unless (defined $payload->{id} && defined $payload->{proof}) {
    my $res = Plack::Response->new(400);
    $res->content_type('text/plain');
    $res->body(qw{'id' and 'proof' must be set in payload});
    return $res->finalize;
  }

  my $res = $req->new_response(200);
  $res->content_type('application/json');
  $res->body(encode_json({}));
  return $res->finalize;
};

builder {
  mount q{/} => $post_handler;
};

__END__
