#
# $Id: Online.pm,v 1.4 2006/12/14 17:50:33 gomor Exp $
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
   unlinkOnStop
   _pid
   _sName
   _sDataAwaiting
   _firstTime
);
__PACKAGE__->cgBuildIndices;
__PACKAGE__->cgBuildAccessorsScalar(\@AS);

BEGIN {
   my $osname = {
      cygwin  => \&_killTcpdumpWin32,
      MSWin32 => \&_killTcpdumpWin32,
   };

   *_killTcpdump = $osname->{$^O} || \&_killTcpdumpOther;
}

no strict 'vars';

use Carp;
use Net::Pcap;
use Time::HiRes qw(gettimeofday);
use Storable qw(lock_store lock_retrieve);
use Net::Frame::Layer qw(:subs);

sub new {
   my $int = getRandom32bitsInt();
   my $self = shift->SUPER::new(
      timeoutOnNext  => 3,
      timeout        => 0,
      promisc        => 0,
      unlinkOnStop   => 1,
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
      or carp("@{[(caller(0))[3]]}: lock_store: @{[$_[0]->[$___sName]]}: $!\n");
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

sub start {
   my $self = shift;

   $self->[$__isRunning] = 1;

   if (-f $self->[$__file] && ! $self->[$__overwrite]) {
      croak("We will not overwrite a file by default. Use `overwrite' ".
            "attribute to do it.\n");
   }
   $self->_sStore(0);
   $self->_sWaitFileSize;
   $self->_startTcpdump;
   $self->_openFile;

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
   return if     $self->isSon;

   $self->_killTcpdump;
   $self->[$___pid] = undef;

   Net::Pcap::close($self->[$___pcapd]);
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
      1514,
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

   $self->[$__firstLayer] = Net::Pcap::datalink($self->[$___pcapd]);
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

sub nextAll { print "XXX: Dump::nextAll: broken, next() does not return Simple objects anymore\n" }

sub getFramesFor { shift->_dumpGetFramesFor(@_) }
sub store        { shift->_dumpStore(@_)        }
sub flush        { shift->_dumpFlush(@_)        }

1;

__END__

=head1 NAME

Net::Frame::Dump::Online - tcpdump like implementation, online mode

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

=item B<getStats>

=item B<isFather>

=item B<isSon>

=item B<next>

=item B<nextAll>

=item B<store>

=item B<flush>

=item B<timeoutReset>

=back

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2006, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut
