use v5.42;
use strictures 2;
use English                 qw(-no_match_vars);
use Test2::V0               qw( done_testing is note ok subtest );
use Test2::Tools::Compare   qw( like );
use Test2::Tools::Exception qw( lives );

use GL::Runtime::Test ();
use GL::LogLine       ();

subtest 'logline' => sub {
  my $rt = GL::Runtime::Test->new;

  ok(
    lives {
      $rt->log->debug('0');
      my $logline = $rt->log->output('test')->array->[-1];
      GL::LogLine->parse($logline->{message});
    },
  ) or note($EVAL_ERROR);

  done_testing;
};

done_testing;

__END__
