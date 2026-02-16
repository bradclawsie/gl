package GL::Runtime::Test;
use v5.42;
use strictures 2;
use Carp                 qw( croak );
use Log::Dispatch::Array ();
use Path::Tiny           qw( path );
use Time::Piece          qw( localtime );
use Types::Standard      qw( ArrayRef Defined Object );

use GL::LogLine;

our $VERSION   = '0.0.1';
our $AUTHORITY = 'cpan:bclawsie';

use Marlin
  -with => ['GL::Runtime'],

  'dbi!' => {
  isa     => ArrayRef [Defined],
  default => sub {
    return [
      'dbi:SQLite:dbname=:memory:',
      q{}, q{},
      {
        RaiseError                       => 1,
        PrintError                       => 0,
        AutoCommit                       => 1,
        sqlite_unicode                   => 1,
        sqlite_allow_multiple_statements => 1,
      },
    ];
  }
  },

  'dispatcher!' => {
  isa     => Object,
  default => sub {
    return Log::Dispatch::Array->new(
      name      => 'test',
      min_level => 'debug',
      callbacks => sub (%args) {
        my $t       = localtime;
        my $date    = $t->strftime(GL::LogLine->date_format);
        my $level   = $args{level};
        my $message = $args{message};

        my ($file, $line);
        my $depth = 0;
        while (my @frame = caller($depth)) {
          if ($frame[0] !~ /^Log::Dispatch/x) {
            $file = $frame[1];
            $line = $frame[2];
            last;
          }
          $depth++;
        }
        $file //= 'unknown';
        $line //= 0;

        return "[${date}] [${level}] ${message} (${file}:${line})";
      },
    );
  },
  },

  'mode!' => {constant => 'test'};

sub BUILD ($self, $args) {

  # Build :memory: db.
  my $schema_file = $ENV{SCHEMA}                   || croak 'SCHEMA not set';
  my $schema      = path($schema_file)->slurp_utf8 || croak $!;
  $self->db->txn(fixup => sub ($dbh) { $dbh->do($schema) });

  # Finish setting up root.
  $self->root->owner->key_version($self->encryption_key_version);
}

__END__
