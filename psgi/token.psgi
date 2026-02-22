# vim: set filetype=perl :
use v5.42;
use strictures 2;
use Carp           qw( croak );
use Plack::Builder qw( builder enable mount );

our $VERSION   = '0.01';
our $AUTHORITY = 'cpan:bclawsie';

__END__
