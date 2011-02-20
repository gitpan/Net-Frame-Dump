#
# $Id: Online2.pm 332 2011-02-16 10:42:07Z gomor $
#
package Net::Frame::Dump::Online2;
use strict;
use warnings;

use Net::Frame::Dump qw(:consts);
our @ISA = qw(Net::Frame::Dump);

our @AS = qw(
   dev
   timeoutOnNext
   timeout
   promisc
   snaplen
   _firstTime
);
__PACKAGE__->cgBuildIndices;
__PACKAGE__->cgBuildAccessorsScalar(\@AS);

BEGIN {
   my $osname = {
      cygwin  => [ \&_checkWin32, ],
      MSWin32 => [ \&_checkWin32, ],
   };

   *_check = $osname->{$^O}->[0] || \&_checkOther;
}

no strict 'vars';

use Carp;
use Net::Pcap;
use Time::HiRes qw(gettimeofday);
use Net::Frame::Layer qw(:subs);

sub _checkWin32 { return 1; }

sub _checkOther {
   if ($>) {
      warn("Must be EUID 0 (or equivalent) to open a device for live capture.\n");
      return;
   }
   return 1;
}

sub new {
   my $int = getRandom32bitsInt();
   my $self = shift->_dumpNew(
      timeoutOnNext => 3,
      timeout       => 0,
      promisc       => 0,
      snaplen       => 1514,
      @_,
   );

   unless ($self->[$__dev]) {
      warn("You MUST pass `dev' attribute\n");
      return;
   }

   return $self;
}

sub start {
   my $self = shift;

   _check() or return;

   $self->[$__isRunning] = 1;

   my $err;
   my $pd = Net::Pcap::open_live(
      $self->[$__dev],
      $self->[$__snaplen],
      $self->[$__promisc],
      100,
      \$err,
   );
   unless ($pd) {
      warn("@{[(caller(0))[3]]}: open_live: $err\n");
      return;
   }

   my $net  = 0;
   my $mask = 0;
   Net::Pcap::lookupnet($self->[$__dev], \$net, \$mask, \$err);
   if ($err) {
      warn("@{[(caller(0))[3]]}: lookupnet: $err\n");
      return;
   }

   my $fcode;
   if (Net::Pcap::compile($pd, \$fcode, $self->[$__filter], 0, $mask) < 0) {
      warn("@{[(caller(0))[3]]}: compile: ". Net::Pcap::geterr($pd). "\n");
      return;
   }

   if (Net::Pcap::setfilter($pd, $fcode) < 0) {
      warn("@{[(caller(0))[3]]}: setfilter: ". Net::Pcap::geterr($pd). "\n");
      return;
   }

   my $r = Net::Pcap::setnonblock($pd, 1, \$err);
   if ($r == -1) {
      warn("@{[(caller(0))[3]]}: setnonblock: $err\n");
      return;
   }

   $self->_pcapd($pd);
   $self->_dumpGetFirstLayer;

   #$SIG{INT}  = sub { $self->_printStats };
   #$SIG{TERM} = sub { $self->_printStats };
   #$self->cgDebugPrint(1, "dev:    [@{[$self->[$__dev]]}]\n".
                          #"file:   [@{[$self->[$__file]]}]\n".
                          #"filter: [@{[$self->[$__filter]]}]");

   return 1;
}

sub stop {
   my $self = shift;

   return unless $self->[$__isRunning];

   Net::Pcap::close($self->[$___pcapd]);
   $self->[$__isRunning] = 0;

   return 1;
}

sub getStats {
   my $self = shift;

   unless ($self->[$___pcapd]) {
      carp("@{[(caller(0))[3]]}: unable to get stats, no pcap descriptor ".
           "opened.\n");
      return;
   }

   my %stats;
   Net::Pcap::stats($self->[$___pcapd], \%stats);
   return \%stats;
}

sub _printStats {
   my $self = shift;

   my $stats = $self->getStats;
   Net::Pcap::close($self->[$___pcapd]);

   $self->cgDebugPrint(1, 'Frames received  : '.$stats->{ps_recv});
   $self->cgDebugPrint(1, 'Frames dropped   : '.$stats->{ps_drop});
   $self->cgDebugPrint(1, 'Frames if dropped: '.$stats->{ps_ifdrop});

   return 1;
}

sub _getNextAwaitingFrame {
   my $self = shift;
   $self->_dumpPcapNextEx;
}

sub _nextTimeoutHandle {
   my $self = shift;

   # Handle timeout
   my $thisTime = gettimeofday()      if     $self->[$__timeoutOnNext];
   $self->[$___firstTime] = $thisTime unless $self->[$___firstTime];

   if ($self->[$__timeoutOnNext] && $self->[$___firstTime]) {
      if (($thisTime - $self->[$___firstTime]) > $self->[$__timeoutOnNext]) {
         $self->[$__timeout]    = 1;
         $self->[$___firstTime] = 0;
         $self->cgDebugPrint(1, "Timeout occured");
         return;
      }
   }
   return 1;
}

sub _nextTimeoutReset { shift->[$___firstTime] = 0 }

sub timeoutReset { shift->[$__timeout] = 0 }

sub next {
   my $self = shift;

   $self->_nextTimeoutHandle or return;

   my $frame = $self->_getNextAwaitingFrame;
   $self->_nextTimeoutReset if $frame;

   return $frame;
}

sub getFramesFor { shift->_dumpGetFramesFor(@_) }
sub store        { shift->_dumpStore(@_)        }
sub flush        { shift->_dumpFlush(@_)        }

1;

__END__

=head1 NAME

Net::Frame::Dump::Online2 - tcpdump like implementation, online mode and non-blocking

=head1 SYNOPSIS

   use Net::Frame::Dump::Online2;

   #
   # Simply create a Dump object
   #
   my $oDump = Net::Frame::Dump::Online2->new(
      dev => 'eth0',
   );

   $oDump->start;

   # Gather frames
   while (1) {
      if (my $f = $oDump->next) {
         my $raw            = $f->{raw};
         my $firstLayerType = $f->{firstLayer};
         my $timestamp      = $f->{timestamp};
      }
   }

   $oDump->stop;

   #
   # Default parameters on creation
   #
   my $oDumpDefault = Net::Frame::Dump::Online->new(
      dev            => undef,
      timeoutOnNext  => 3,
      timeout        => 0,
      promisc        => 0,
      filter         => '',
      isRunning      => 0,
      keepTimestamp  => 0,
      frames         => [],
   );

=head1 DESCRIPTION

This module implements a tcpdump-like program, for live capture from networks.

=head1 ATTRIBUTES

=over 4

=item B<dev>

The network interface to listen on. No default value.

=item B<timeoutOnNext>

Each time you call B<next> method, an internal counter is updated. This counter tells you if you have not received any data since B<timeoutOnNext> seconds. When a timeout occure, B<timeout> is set to true.

=item B<timeout>

When B<timeoutOnNext> seconds has been reached, this variable is set to true, and never reset. See B<timeoutReset> if you want to reset it.

=item B<snaplen>

If you want to capture a different snaplen, set it a number. Default to 1514.

=item B<promisc>

By default, interface is not put into promiscuous mode, set this parameter to true if you want it.

=back

The following are inherited attributes:

=over 4

=item B<filter>

Pcap filter to use. Default to no filter.

=item B<firstLayer>

Stores information about the first layer type contained on read frame. This attribute is filled only after a call to B<start> method.

=item B<isRunning>

Returns true if a call to B<start> has been done, false otherwise or if a call to B<stop> has been done.

=item B<keepTimestamp>

Sometimes, when frames are captured and saved to a .pcap file, timestamps sucks. That is, you send a frame, and receive the reply, but your request appear to have been sent after the reply. So, to correct that, you can use B<Net::Frame::Dump> own timestamping system. The default is 0. Set it manually to 1 if you need original .pcap frames timestamps.

=back

=head1 METHODS

=over 4

=item B<new>

=item B<new> (hash)

Object constructor. You can pass attributes that will overwrite default ones. See B<SYNOPSIS> for default values.

=item B<start>

When you want to start reading frames from network, call this method.

=item B<stop>

When you want to stop reading frames from network, call this method.

=item B<next>

Returns the next captured frame; undef if none awaiting. Each time this method is called, a comparison is done to see if no frame has been captured during B<timeoutOnNext> number of seconds. If so, B<timeout> attribute is set to 1 to reflect the pending timeout.

=item B<store> (B<Net::Frame::Simple> object)

This method will store internally, sorted, the B<Net::Frame::Simple> object passed as a single parameter. B<getKey> methods, implemented in various B<Net::Frame::Layer> objects will be used to efficiently retrieve (via B<getKeyReverse> method) frames.

Basically, it is used to make B<recv> method (from B<Net::Frame::Simple>) to retrieve quickly the reply frame for a request frame.

=item B<getFramesFor> (B<Net::Frame::Simple> object)

This will return an array of possible reply frames for the specified B<Net::Frame::Simple> object. For example, reply frames for a UDP probe will be all the frames which have the same source port and destination port as the request.

=item B<flush>

Will flush stored frames, the one which have been stored via B<store> method.

=item B<timeoutReset>

Reset the internal timeout state (B<timeout> attribute).

=item B<getStats>

Tries to get packet statistics on an open descriptor. It returns a reference to a hash that has to following fields: B<ps_recv>, B<ps_drop>, B<ps_ifdrop>.

=back

=head1 SEE ALSO

L<Net::Frame::Dump>

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2006-2011, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut
