#
# $Id: Offline.pm 95 2008-02-16 16:56:59Z gomor $
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

sub new { shift->_dumpNew(@_) }

sub _openFile {
   my $self = shift;

   my $err;
   $self->[$___pcapd] = Net::Pcap::open_offline($self->[$__file], \$err);
   unless ($self->[$___pcapd]) {
      croak("@{[(caller(0))[3]]}: Net::Pcap::open_offline: ".
            "@{[$self->[$__file]]}: $err\n");
   }

   $self->_dumpGetFirstLayer;
}

sub _setFilter {
   my $self = shift;
   my $str = $self->[$__filter];

   return unless $str;

   my $filter;
   Net::Pcap::compile($self->[$___pcapd], \$filter, $str, 0, 0);
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

sub next         { shift->_dumpPcapNext(@_)     }
sub getFramesFor { shift->_dumpGetFramesFor(@_) }
sub store        { shift->_dumpStore(@_)        }
sub flush        { shift->_dumpFlush(@_)        }

1;

__END__

=head1 NAME

Net::Frame::Dump::Offline - tcpdump like implementation, offline mode

=head1 SYNOPSIS

   use Net::Frame::Dump::Offline;

   #
   # Simple offline anaysis
   #
   my $oDump = Net::Frame::Dump::Offline->new(file => $file);

   $oDump->start;

   my $count = 0;
   while (my $h = $oDump->next) {
      my $f = Net::Frame::Simple->new(
         raw        => $h->{raw},
         firstLayer => $h->{firstLayer},
         timestamp  => $h->{timestamp},
      );
      my $len = length($h->{raw});
      print 'o Frame number: '.$count++." (length: $len)\n";
      print $f->print."\n";
   }

   $oDump->stop;

   #
   # Default parameters on creation
   #
   my $oDumpDefault = Net::Frame::Dump::Offline->new(
      file          => "netframe-tmp-$$.$int.pcap",
      filter        => '',
      isRunning     => 0,
      keepTimestamp => 0,
   );

=head1 DESCRIPTION

This module implements a tcpdump-like program, for offline analysis.

=head1 ATTRIBUTES

The following are inherited attributes:

=over 4

=item B<file>

Name of the .pcap file to read.

=item B<filter>

Pcap filter to use. Default to no filter.

=item B<firstLayer>

Stores information about the first layer type contained on read frame. This attribute is filled only after a call to B<start> method.

=item B<isRunning>

Returns true if a call to start has been done, false otherwise or if a call to stop has been done.

=item B<keepTimestamp>

Sometimes, when frames are captured and saved to a .pcap file, timestamps sucks. That is, you send a frame, and receive the reply, but your request appear to have been sent after the reply. So, to correct that, you can use B<Net::Frame::Dump> own timestamping system. The default is 0. Set it manually to 1 if you need original .pcap frames timestamps.

=back

=head1 METHODS

=over 4

=item B<new>

=item B<new> (hash)

Object constructor. You can pass attributes that will overwrite default ones. See B<SYNOPSIS> for default values.

=item B<start>

When you want to start reading frames from the file, call this method.

=item B<stop>

When you want to stop reading frames from the file, call this method.

=item B<next>

Returns the next captured frame; undef if no more frames are awaiting.

=item B<store> (B<Net::Frame::Simple> object)

This method will store internally, sorted, the B<Net::Frame::Simple> object passed as a single parameter. B<getKey> methods, implemented in various B<Net::Frame::Layer> objects will be used to efficiently retrieve (via B<getKeyReverse> method) frames.

Basically, it is used to make B<recv> method (from B<Net::Frame::Simple>) to retrieve quickly the reply frame for a request frame.

=item B<getFramesFor>

This will return an array of possible reply frames for the specified B<Net::Frame::Simple> object. For example, reply frames for a UDP probe will be all the frames which have the same source port and destination port as the request.

=item B<flush>

Will flush stored frames, the one which have been stored via B<store> method.

=back

=head1 SEE ALSO

L<Net::Frame::Dump>

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2006-2008, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut
