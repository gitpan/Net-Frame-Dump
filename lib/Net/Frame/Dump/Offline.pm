#
# $Id: Offline.pm,v 1.4 2006/12/06 21:15:12 gomor Exp $
#
package Net::Frame::Dump::Offline;
use strict;
use warnings;

use Net::Frame::Dump qw(:consts);
our @ISA = qw(Net::Frame::Dump);
__PACKAGE__->cgBuildIndices;

no strict 'vars';

use Carp;
use Net::Pcap;
use Time::HiRes qw(gettimeofday);

sub new { shift->SUPER::new(@_) }

sub _openFile {
   my $self = shift;

   my $err;
   $self->[$___pcapd] = Net::Pcap::open_offline($self->[$__file], \$err);
   unless ($self->[$___pcapd]) {
      croak("@{[(caller(0))[3]]}: Net::Pcap::open_offline: ".
            "@{[$self->[$__file]]}: $err\n");
   }

   $self->[$__link] = Net::Pcap::datalink($self->[$___pcapd]);
}

sub _setFilter {
   my $self = shift;
   my $str = $self->[$__filter];

   return unless $str;

   my ($net, $mask, $err);
   Net::Pcap::lookupnet($self->[$__dev], \$net, \$mask, \$err);
   if ($err) {
      croak("@{[(caller(0))[3]]}: Net::Pcap::lookupnet: @{[$self->[$__dev]]}: ".
            "$err\n");
   }

   my $filter;
   Net::Pcap::compile($self->[$___pcapd], \$filter, $str, 0,
                      $mask);
   unless ($filter) {
      croak("@{[(caller(0))[3]]}: Net::Pcap::compile: error\n");
   }

   Net::Pcap::setfilter($self->[$___pcapd], $filter);
}

sub start {
   my $self = shift;

   $self->[$__isRunning] = 1;

   if (! -f $self->[$__file]) {
      croak("File does not exists: ".$self->[$__file]."\n");
   }

   $self->_openFile;
   $self->_setFilter;

   1;
}

sub stop {
   my $self = shift;

   return unless $self->[$__isRunning];

   Net::Pcap::close($self->[$___pcapd]);
   $self->[$__isRunning] = 0;

   1;
}

sub next { shift->_dumpPcapNext(@_) }

sub nextAll { print "XXX: Dump::nextAll: broken, next() does not return Simple objects anymore\n" }

sub getFramesFor { shift->_dumpGetFramesFor(@_) }
sub store        { shift->_dumpStore(@_)        }
sub flush        { shift->_dumpFlush(@_)        }

1;

__END__

=head1 NAME

Net::Frame::Dump - tcpdump like implementation

=head1 SYNOPSIS

=head1 DESCRIPTION

=head1 ATTRIBUTES

=over 4

=back

=head1 METHODS

=over 4

=item B<new>

=item B<start>

=item B<stop>

=item B<getFramesFor>

=item B<next>

=item B<nextAll>

=item B<store>

=item B<flush>

=back

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2006, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut
