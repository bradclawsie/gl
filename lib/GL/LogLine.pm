package GL::LogLine;
use v5.42;
use strictures 2;
use Carp                   qw( croak );
use Time::Piece            qw( localtime );
use Type::Params           qw( signature_for );
use Types::Common::Numeric qw( PositiveInt );
use Types::Standard        qw( ClassName InstanceOf Str );

our $VERSION   = '0.0.1';
our $AUTHORITY = 'cpan:bclawsie';

use Marlin
  date                   => InstanceOf ['Time::Piece'],
  qw(level message file) => Str,
  line                   => PositiveInt,
  date_format            => {constant => '%Y%m%d %H:%M:%S %z'};

signature_for logdispatch_callback => (
  method     => false,
  positional => [ClassName],
);

sub logdispatch_callback ($class) {
  return sub (%args) {
    my $t       = localtime;
    my $date    = $t->strftime($class->date_format);
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
  };
}

signature_for parse => (
  method     => false,
  positional => [ ClassName, Str ],
);

sub parse ($class, $raw) {

  # [YYYYMMDD HH:MM:SS TZ] [level] some message text (/path/to/file:line-number)
  my $re = qr{
    ^\s*
    \[(?<date>([^]]+))\]
    \s
    \[(?<level>([^]]+))\]
    \s
    (?<message>(.*?))
    \s
    [(]
    (?<file>([^:]+))
    :
    (?<line>(\d+))
    [)]
    \s*
    $
  }x;

  if ($raw =~ m/$re/x) {
    my $parsed_time;
    try {
      $parsed_time =
        Time::Piece->strptime(${^CAPTURE}{date}, $class->date_format);
    }
    catch ($e) {
      croak 'bad log line date: ' . $e;
    }

    return $class->new(
      date    => $parsed_time,
      level   => ${^CAPTURE}{level},
      message => ${^CAPTURE}{message},
      file    => ${^CAPTURE}{file},
      line    => ${^CAPTURE}{line},
    );
  }
  croak 'bad log line';
}

signature_for log_format => (
  method     => true,
  positional => [],
);

sub log_format ($self) {
  my $date    = $self->date->strftime($self->date_format);
  my $level   = $self->level;
  my $message = $self->message;
  my $file    = $self->file;
  my $line    = $self->line;
  return "[${date}] [${level}] ${message} (${file}:${line})";
}

__END__
