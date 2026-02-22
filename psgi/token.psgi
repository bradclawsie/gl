# vim: set filetype=perl :
use v5.42;
use strictures 2;
use JSON::MaybeXS  qw( encode_json );
use Plack::Builder qw( builder mount );
use Plack::Request;
use Plack::Response;

our $VERSION   = '0.01';
our $AUTHORITY = 'cpan:bclawsie';

my $post_handler = sub ($env) {
  my $req = Plack::Request->new($env);

  if ($req->method ne 'POST') {
    return [
      405,
      [ 'Content-Type' => 'text/plain' ],
      ['Endpoint only accepts POST requests.'],
    ];
  }

  my $res = Plack::Response->new(200);
  $res->content_type('application/json');
  $res->body(encode_json({}));
  return $res->finalize;
};

builder {
  mount q{/} => $post_handler;
};

__END__
