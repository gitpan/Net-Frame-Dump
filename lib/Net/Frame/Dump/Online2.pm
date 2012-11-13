#
# $Id: Online2.pm 358 2012-11-13 19:16:33Z gomor $
#
package Net::Frame::Dump::Online2;
use strict;
use warnings;

use base qw(Net::Frame::Dump);
our @AS = qw(
   dev
   timeoutOnNext
   timeout
   promisc
   snaplen
   file
   overwrite
   _firstTime
   _pid
   _sel
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

use Net::Frame::Dump qw(:consts);

use IO::Select;
use Net::Pcap;
use Time::HiRes qw(gettimeofday);
use Net::Frame::Layer qw(:subs);

sub _checkWin32 { return 1; }

sub _checkOther {
   if ($>) {
      die("[-] Net::Frame::Dump::Online2: Must be EUID 0 (or equivalent) to ".
          "open a device for live capture\n");
   }
   return 1;
}

sub new {
   my $self = shift->SUPER::new(
      timeoutOnNext => 3,
      timeout       => 0,
      promisc       => 0,
      snaplen       => 1514,
      file          => '',
      overwrite     => 0,
      @_,
   );

   if (!defined($self->dev)) {
      print("[-] ".__PACKAGE__.": You MUST pass `dev' attribute\n");
      return;
   }

   return $self;
}

sub start {
   my $self = shift;

   _check() or return;

   $self->isRunning(1);

   if (length($self->file)) {
      if (-f $self->file && ! $self->overwrite) {
         print("[-] ".__PACKAGE__.": We will not overwrite a file by default. ".
               "Use `overwrite' attribute to do it.\n");
         return;
      }
   }

   my $err;
   my $pd = Net::Pcap::open_live(
      $self->dev,
      $self->snaplen,
      $self->promisc,
      100,
      \$err,
   );
   unless ($pd) {
      print("[-] ".__PACKAGE__.": open_live: $err\n");
      return;
   }

   my $net  = 0;
   my $mask = 0;
   Net::Pcap::lookupnet($self->dev, \$net, \$mask, \$err);
   if ($err) {
      print("[!] ".__PACKAGE__.": lookupnet: $err\n");
   }

   my $fcode;
   if (Net::Pcap::compile($pd, \$fcode, $self->filter, 0, $mask) < 0) {
      print("[-] ".__PACKAGE__.": compile: ". Net::Pcap::geterr($pd). "\n");
      return;
   }

   if (Net::Pcap::setfilter($pd, $fcode) < 0) {
      print("[-] ".__PACKAGE__.": setfilter: ". Net::Pcap::geterr($pd). "\n");
      return;
   }

   # Avoid nonblock mode when capture only mode chosen: don't eat 100% CPU
   if (! length($self->file)) {
      my $r = Net::Pcap::setnonblock($pd, 1, \$err);
      if ($r == -1) {
         print("[-] ".__PACKAGE__.": setnonblock: $err\n");
         return;
      }

      # Gather a file descriptor to use by select()
      my $fd  = Net::Pcap::get_selectable_fd($pd);
      my $sel = IO::Select->new;
      $sel->add($fd);
      $self->_sel($sel);
   }

   $self->_pcapd($pd);
   $self->getFirstLayer;

   if (length($self->file)) {
      my $pid = fork();
      if (! defined($pid)) {
         die("[-] ".__PACKAGE__.": fork: $!\n");
      }

      if ($pid) {   # Parent
         $self->_pid($pid);
         $SIG{CHLD} = 'IGNORE';
         return 1;
      }
      else {   # Son
         $self->_pid(0);
         $self->_pcapd($pd);

         my $dumper = Net::Pcap::dump_open($pd, $self->file);
         if (! defined($dumper)) {
            print("[-] ".__PACKAGE__.": dump_open: ".Net::Pcap::geterr($pd).
                  "\n");
            exit(1);
         }
         Net::Pcap::dump_flush($dumper);

         Net::Pcap::loop($pd, -1, \&_saveCallback, [ $dumper, $self ]);
         exit(0);
      }
   }

   return 1;
}

sub _isFather {
   my $self = shift;
   return $self->_pid;
}

sub _isSon {
   my $self = shift;
   return ! $self->_pid;
}

sub _saveCallback {
   my ($data, $hdr, $pkt) = @_;
   my $p    = $data->[0];
   my $self = $data->[1];

   Net::Pcap::dump($p, $hdr, $pkt);
   Net::Pcap::dump_flush($p);
}

sub _killTcpdump {
   my $self = shift;
   return if $self->_isSon;
   kill('KILL', $self->_pid);
   $self->_pid(undef);
}

sub stop {
   my $self = shift;

   if (! $self->isRunning || $self->_isSon) {
      return;
   }

   # We are in capture mode
   if (length($self->file) && $self->_isFather) {
      $self->_killTcpdump;
   }

   Net::Pcap::close($self->_pcapd);
   $self->_pcapd(undef);
   $self->isRunning(0);

   return 1;
}

sub getStats {
   my $self = shift;

   if (!defined($self->_pcapd)) {
      print("[-] ".__PACKAGE__.": unable to get stats, no pcap descriptor ".
           "opened.\n");
      return;
   }

   my %stats;
   Net::Pcap::stats($self->_pcapd, \%stats);
   return \%stats;
}

sub _printStats {
   my $self = shift;

   my $stats = $self->getStats;
   Net::Pcap::close($self->_pcapd);

   $self->cgDebugPrint(1, 'Frames received  : '.$stats->{ps_recv});
   $self->cgDebugPrint(1, 'Frames dropped   : '.$stats->{ps_drop});
   $self->cgDebugPrint(1, 'Frames if dropped: '.$stats->{ps_ifdrop});

   return 1;
}

sub _getNextAwaitingFrame {
   my $self = shift;
   return $self->nextEx;
}

sub _nextTimeoutHandle {
   my $self = shift;

   # Handle timeout
   my $thisTime = gettimeofday();
   if ($self->timeoutOnNext && !$self->_firstTime) {
      $self->_firstTime($thisTime);
   }

   if ($self->timeoutOnNext && $self->_firstTime) {
      if (($thisTime - $self->_firstTime) > $self->timeoutOnNext) {
         $self->timeout(1);
         $self->_firstTime(0);
         $self->cgDebugPrint(1, "Timeout occured");
         return;
      }
   }

   return 1;
}

sub _nextTimeoutReset { shift->_firstTime(0) }

sub timeoutReset { shift->timeout(0) }

sub next {
   my $self = shift;

   if (length($self->file)) {
      die("[-] ".__PACKAGE__.": next method not available while in ".
          "capture mode.\n");
   }

   my $sel = $self->_sel;
   if (my @read = $sel->can_read($self->timeoutOnNext)) {
      $self->_nextTimeoutReset;
      my $frame = $self->_getNextAwaitingFrame;
      return $frame;
   }

   # If we are here, a timeout has occured
   $self->_nextTimeoutHandle;

   return;
}

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
   my $oDumpDefault = Net::Frame::Dump::Online2->new(
      timeoutOnNext => 3,
      timeout       => 0,
      promisc       => 0,
      snaplen       => 1514,
      file          => '',
      overwrite     => 0,
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

Copyright (c) 2006-2012, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut
