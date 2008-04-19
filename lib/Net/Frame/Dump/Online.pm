#
# $Id: Online.pm 152 2008-04-19 16:52:38Z gomor $
#
package Net::Frame::Dump::Online;
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
   unlinkOnStop
   onRecv
   onRecvCount
   onRecvData
   _pid
   _sName
   _sDataAwaiting
   _firstTime
);
__PACKAGE__->cgBuildIndices;
__PACKAGE__->cgBuildAccessorsScalar(\@AS);

BEGIN {
   my $osname = {
      cygwin  => [ \&_killTcpdumpWin32, \&_checkWin32, ],
      MSWin32 => [ \&_killTcpdumpWin32, \&_checkWin32, ],
   };

   *_killTcpdump = $osname->{$^O}->[0] || \&_killTcpdumpOther;
   *_check       = $osname->{$^O}->[1] || \&_checkOther;
}

no strict 'vars';

use Carp;
use Net::Pcap;
use Time::HiRes qw(gettimeofday);
use Storable qw(lock_store lock_retrieve);
use Net::Frame::Layer qw(:subs);

sub _checkWin32 { }

sub _checkOther {
   croak("Must be EUID 0 (or equivalent) to open a device for live capture.\n")
      if $>;
}

sub new {
   _check();

   my $int = getRandom32bitsInt();
   my $self = shift->_dumpNew(
      timeoutOnNext  => 3,
      timeout        => 0,
      promisc        => 0,
      snaplen        => 1514,
      unlinkOnStop   => 1,
      onRecvCount    => -1,
      _sName         => "netframe-tmp-$$.$int.storable",
      _sDataAwaiting => 0,
      @_,
   );

   unless ($self->[$__dev]) {
      croak("You MUST pass `dev' attribute\n");
   }

   $self;
}

sub _sStore {
   lock_store(\$_[1], $_[0]->[$___sName])
      or do {
         carp("@{[(caller(0))[3]]}: lock_store: @{[$_[0]->[$___sName]]}: $!\n");
         return undef;
      };
}
sub _sRetrieve { ${lock_retrieve(shift->[$___sName])} }

sub _sWaitFile {
   my $self = shift;
   my $startTime = gettimeofday();
   my $thisTime  = $startTime;
   while (! -f $self->[$___sName]) {
      if ($thisTime - $startTime > 10) {
         croak("@{[(caller(0))[3]]}: too long for file creation: ".
               $self->[$___sName]."\n")
      }
      $thisTime = gettimeofday();
   }
}

sub _sWaitFileSize {
   my $self = shift;

   $self->_sWaitFile;

   my $startTime = gettimeofday();
   my $thisTime  = $startTime;
   while (! ((stat($self->[$___sName]))[7] > 0)) {
      if ($thisTime - $startTime > 10) {
         $self->_clean;
         croak("@{[(caller(0))[3]]}: too long for file creation2: ".
               $self->[$___sName]."\n")
      }
      $thisTime = gettimeofday();
   }
}

sub _startOnRecv {
   my $self = shift;

   my $err;
   my $pd = Net::Pcap::open_live(
      $self->[$__dev],
      $self->[$__snaplen],
      $self->[$__promisc],
      1000,
      \$err,
   );
   unless ($pd) {
      croak("@{[(caller(0))[3]]}: open_live: $err\n");
   }
   $self->[$___pcapd] = $pd;

   my $net  = 0;
   my $mask = 0;
   Net::Pcap::lookupnet($self->[$__dev], \$net, \$mask, \$err);
   if ($err) {
      carp("@{[(caller(0))[3]]}: lookupnet: $err\n");
      return undef;
   }

   my $fcode;
   if (Net::Pcap::compile($pd, \$fcode, $self->[$__filter], 0, $mask) < 0) {
      croak("@{[(caller(0))[3]]}: compile: ". Net::Pcap::geterr($pd). "\n");
   }

   if (Net::Pcap::setfilter($pd, $fcode) < 0) {
      croak("@{[(caller(0))[3]]}: setfilter: ". Net::Pcap::geterr($pd). "\n");
   }

   $self->_dumpGetFirstLayer;

   # Setup onRecv enforced code, to make it simpler for user
   my $callback = sub {
      my ($userData, $hdr, $pkt) = @_;
      my $h = {
         raw        => $pkt,
         timestamp  => $hdr->{tv_sec}.'.'.sprintf("%06d", $hdr->{tv_usec}),
         firstLayer => $self->firstLayer,
      };
      &{$self->onRecv}($h, $userData);
   };

   Net::Pcap::loop(
      $pd, $self->[$__onRecvCount], $callback, $self->[$__onRecvData],
   );
}

sub start {
   my $self = shift;

   $self->[$__isRunning] = 1;

   if (-f $self->[$__file] && ! $self->[$__overwrite]) {
      croak("We will not overwrite a file by default. Use `overwrite' ".
            "attribute to do it.\n");
   }

   if ($self->onRecv) {
      $self->_startOnRecv;
   }
   else {
      $self->_sStore(0);
      $self->_sWaitFileSize;
      $self->_startTcpdump;
      $self->_openFile;
   }

   1;
}

sub _clean {
   my $self = shift;
   if ($self->[$__unlinkOnStop] && $self->[$__file] && -f $self->[$__file]) {
      unlink($self->[$__file]);
      $self->cgDebugPrint(1, "@{[$self->file]} removed");
   }
   if ($self->[$___sName] && -f $self->[$___sName]) {
      unlink($self->[$___sName]);
   }
}

sub stop {
   my $self = shift;

   $self->_clean;

   return unless $self->[$__isRunning];

   if ($self->onRecv && $self->[$___pcapd]) {
      Net::Pcap::breakloop($self->[$___pcapd]);
      Net::Pcap::close($self->[$___pcapd]);
   }
   else {
      return if $self->isSon;

      $self->_killTcpdump;
      $self->[$___pid] = undef;

      Net::Pcap::close($self->[$___pcapd]);
   }

   $self->[$__isRunning] = 0;

   1;
}

sub getStats {
   my $self = shift;

   unless ($self->[$___pcapd]) {
      carp("@{[(caller(0))[3]]}: unable to get stats, no pcap descriptor ".
           "opened.\n");
      return undef;
   }

   my %stats;
   Net::Pcap::stats($self->[$___pcapd], \%stats);
   \%stats;
}

sub isFather { shift->[$___pid] ? 1 : 0 }
sub isSon    { shift->[$___pid] ? 0 : 1 }

sub _sonPrintStats {
   my $self = shift;

   my $stats = $self->getStats;
   Net::Pcap::breakloop($self->[$___pcapd]);
   Net::Pcap::close($self->[$___pcapd]);

   $self->cgDebugPrint(1, 'Frames received  : '.$stats->{ps_recv});
   $self->cgDebugPrint(1, 'Frames dropped   : '.$stats->{ps_drop});
   $self->cgDebugPrint(1, 'Frames if dropped: '.$stats->{ps_ifdrop});
   exit(0);
}

sub _startTcpdump {
   my $self = shift;

   my $err;
   my $pd = Net::Pcap::open_live(
      $self->[$__dev],
      $self->[$__snaplen],
      $self->[$__promisc],
      1000,
      \$err,
   );
   unless ($pd) {
      croak("@{[(caller(0))[3]]}: open_live: $err\n");
   }

   my $net  = 0;
   my $mask = 0;
   Net::Pcap::lookupnet($self->[$__dev], \$net, \$mask, \$err);
   if ($err) {
      carp("@{[(caller(0))[3]]}: lookupnet: $err\n");
      return undef;
   }

   my $fcode;
   if (Net::Pcap::compile($pd, \$fcode, $self->[$__filter], 0, $mask) < 0) {
      croak("@{[(caller(0))[3]]}: compile: ". Net::Pcap::geterr($pd). "\n");
   }

   if (Net::Pcap::setfilter($pd, $fcode) < 0) {
      croak("@{[(caller(0))[3]]}: setfilter: ". Net::Pcap::geterr($pd). "\n");
   }

   my $p = Net::Pcap::dump_open($pd, $self->[$__file]);
   unless ($p) {
      croak("@{[(caller(0))[3]]}: dump_open: ". Net::Pcap::geterr($pd). "\n");
   }
   Net::Pcap::dump_flush($p);

   $SIG{CHLD} = 'IGNORE';

   my $pid = fork();
   croak("@{[(caller(0))[3]]}: fork: $!\n") unless defined $pid;
   if ($pid) {
      $self->[$___pid] = $pid;
      return 1;
   }
   else {
      $self->[$___pcapd] = $pd;
      $SIG{INT}  = sub { $self->_sonPrintStats };
      $SIG{TERM} = sub { $self->_sonPrintStats };
      $self->cgDebugPrint(1, "dev:    [@{[$self->[$__dev]]}]\n".
                             "file:   [@{[$self->[$__file]]}]\n".
                             "filter: [@{[$self->[$__filter]]}]");
      Net::Pcap::loop($pd, -1, \&_tcpdumpCallback, [ $p, $self ]);
      Net::Pcap::close($pd);
      exit(0);
   }
}

sub _tcpdumpCallback {
   my ($data, $hdr, $pkt) = @_;
   my $p    = $data->[0];
   my $self = $data->[1];

   Net::Pcap::dump($p, $hdr, $pkt);
   Net::Pcap::dump_flush($p);

   my $n = $self->_sRetrieve;
   $self->_sStore(++$n);
}

sub _killTcpdumpWin32 {
   my $self = shift;
   return unless $self->[$___pid];
   kill('KILL', $self->[$___pid]);
}

sub _killTcpdumpOther {
   my $self = shift;
   return unless $self->[$___pid];
   kill('TERM', $self->[$___pid]);
}

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

sub _getNextAwaitingFrame {
   my $self = shift;
   my $last = $self->[$___sDataAwaiting];
   my $new  = $self->_sRetrieve;

   # Return if nothing new is awaiting
   return undef if ($new <= $last);

   $self->[$___sDataAwaiting]++;
   $self->_dumpPcapNext;
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
         return undef;
      }
   }
   1;
}

sub _nextTimeoutReset { shift->[$___firstTime] = 0 }

sub timeoutReset { shift->[$__timeout] = 0 }

sub next {
   my $self = shift;

   $self->_nextTimeoutHandle or return undef;

   my $frame = $self->_getNextAwaitingFrame;
   $self->_nextTimeoutReset if $frame;

   $frame;
}

sub getFramesFor { shift->_dumpGetFramesFor(@_) }
sub store        { shift->_dumpStore(@_)        }
sub flush        { shift->_dumpFlush(@_)        }

1;

__END__

=head1 NAME

Net::Frame::Dump::Online - tcpdump like implementation, online mode

=head1 SYNOPSIS

   use Net::Frame::Dump::Online;

   #
   # Simply create a Dump object
   #
   my $oDump = Net::Frame::Dump::Online->new(
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
   # Create a Dump object, using on-event loop
   #
   sub callOnRecv {
      my ($h, $data) = @_;
      print "Data: $data\n";
      my $oSimple = Net::Frame::Simple->newFromDump($h);
      print $oSimple->print."\n";
   }

   my $oDumpEvent = Net::Frame::Dump::Online->new(
      dev         => 'eth0',
      onRecv      => \&callOnRecv,
      onRecvCount => 1,
      onRecvData  => 'test',
   );

   # Will block here, until $onRecvCount packets read, or a stop() call has 
   # been performed.
   $oDumpEvent->start;

   #
   # Default parameters on creation
   #
   my $oDumpDefault = Net::Frame::Dump::Online->new(
      dev            => undef,
      timeoutOnNext  => 3,
      timeout        => 0,
      promisc        => 0,
      unlinkOnStop   => 1,
      file           => "netframe-tmp-$$.$int.pcap",
      filter         => '',
      overwrite      => 0,
      isRunning      => 0,
      keepTimestamp  => 0,
      onRecvCount    => -1,
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

=item B<unlinkOnStop>

When you call B<stop> method, the generated .pcap file is removed, unless you set this parameter to a false value.

=item B<onRecv>

If you place a reference to a sub in this attribute, it will be called each time a packet is received on the interface. See B<SYNOPSIS> for an example usage.

=item B<onRecvData>

This parameter will store additional data to be passed to B<onRecv> callback.

=item B<onRecvCount>

By default, it is set to read forever packets that reach your network interface. Set it to a positive value to read only B<onRecvCount> frames.

=back

The following are inherited attributes:

=over 4

=item B<file>

Name of the generated .pcap file. See B<SYNOPSIS> for the default name.

=item B<filter>

Pcap filter to use. Default to no filter.

=item B<overwrite>

Overwrites a .pcap file that already exists. Default to not.

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

=item B<isFather>

=item B<isSon>

These methods will tell you if your current process is respectively the father, or son process of B<Net::Frame::Dump::Online> object.

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
