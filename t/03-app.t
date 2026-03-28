use v5.42;
use strictures 2;
use Carp                    qw( croak );
use English                 qw(-no_match_vars);
use HTTP::Request           ();
use Path::Tiny              qw( path );
use Plack::Test             ();
use Plack::Util             ();
use Test2::V0               qw( done_testing is note ok subtest );
use Test2::Tools::Exception qw( lives );

use GL::Runtime::Test ();

our $VERSION   = '0.0.1';
our $AUTHORITY = 'cpan:bclawsie';

my $rt = GL::Runtime::Test->new;

my $psgi_path = $ENV{PSGI_PATH} // croak 'PSGI_PATH';
my $app       = Plack::Util::load_psgi(path($psgi_path, 'app.psgi'));

my $test = Plack::Test->create($app);

subtest 'not-found' => sub {
  ok(
    lives {
      my $req = HTTP::Request->new(GET => q{/not-found});
      my $res = $test->request($req);

      is(404, $res->code, 'not-found ok');
    },
    'not-found lives'
  ) or note($EVAL_ERROR);
};

done_testing;

__END__
