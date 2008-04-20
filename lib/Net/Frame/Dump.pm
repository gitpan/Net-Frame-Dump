#
# $Id: Dump.pm 154 2008-04-20 10:20:40Z gomor $
#
package Net::Frame::Dump;
use strict;
use warnings;

our $VERSION = '1.04';

require Class::Gomor::Array;
require Exporter;
our @ISA = qw(Class::Gomor::Array Exporter);

our %EXPORT_TAGS = (
   consts => [qw(
      NF_DUMP_LAYER_NULL
      NF_DUMP_LAYER_ETH
      NF_DUMP_LAYER_RAW
      NF_DUMP_LAYER_SLL
      NF_DUMP_LAYER_PPP
      NF_DUMP_LAYER_80211RADIO
   )],
);
our @EXPORT_OK = (
   @{$EXPORT_TAGS{consts}},
);

use constant NF_DUMP_LAYER_NULL => 0;
use constant NF_DUMP_LAYER_ETH  => 1;
use constant NF_DUMP_LAYER_PPP  => 9;
use constant NF_DUMP_LAYER_RAW  => 12;
use constant NF_DUMP_LAYER_SLL  => 113;
use constant NF_DUMP_LAYER_80211RADIO => 127;

our @AS = qw(
   file
   filter
   overwrite
   firstLayer
   isRunning
   keepTimestamp
   _framesStored
   _pcapd
   _dumper
);
our @AA = qw(
   frames
);
__PACKAGE__->cgBuildIndices;
__PACKAGE__->cgBuildAccessorsScalar(\@AS);
__PACKAGE__->cgBuildAccessorsArray(\@AA);

use Carp;
use Net::Pcap;
use Time::HiRes qw(gettimeofday);
use Net::Frame::Layer qw(:consts :subs);

sub _dumpNew {
   my $int = getRandom32bitsInt();
   shift->SUPER::new(
      file          => "netframe-tmp-$$.$int.pcap",
      filter        => '',
      overwrite     => 0,
      isRunning     => 0,
      keepTimestamp => 0,
      frames        => [],
      _framesStored => {},
      @_,
   );
}

sub _dumpFlush {
   my $self = shift;
   $self->frames([]);
   $self->_framesStored({});
}

sub _dumpStore {
   my $self = shift;
   my ($oSimple) = @_;

   $self->_dumpFramesStored($oSimple);

   my @frames = $self->frames;
   push @frames, $oSimple;
   $self->frames(\@frames);
}

sub _getTimestamp {
   my $self = shift;
   my ($hdr) = @_;
   $hdr->{tv_sec}.'.'.sprintf("%06d", $hdr->{tv_usec});
}

sub _setTimestamp {
   my $self = shift;
   my @time = Time::HiRes::gettimeofday();
   $time[0].'.'.sprintf("%06d", $time[1]);
}

my $mapLinks = {
   NF_DUMP_LAYER_NULL() => 'NULL',
   NF_DUMP_LAYER_ETH()  => 'ETH',
   NF_DUMP_LAYER_RAW()  => 'RAW',
   NF_DUMP_LAYER_SLL()  => 'SLL',
   NF_DUMP_LAYER_PPP()  => 'PPP',
   NF_DUMP_LAYER_80211RADIO() => '80211RADIO',
};

sub _dumpGetFirstLayer {
   my $self = shift;
   my $link = Net::Pcap::datalink($self->_pcapd);
   $self->firstLayer($mapLinks->{$link} || NF_LAYER_UNKNOWN);
}

sub _dumpPcapNext {
   my $self = shift;

   my %hdr;
   if (my $raw = Net::Pcap::next($self->_pcapd, \%hdr)) {
      my $ts = $self->keepTimestamp ? $self->_getTimestamp(\%hdr)
                                    : $self->_setTimestamp;
      return {
         firstLayer => $self->firstLayer,
         timestamp  => $ts,
         raw        => $raw,
      };
   }

   undef;
}

sub _dumpGetFramesFor {
   my $self = shift;
   my ($oSimple) = @_;

   my $results;
   my $key = $oSimple->getKeyReverse;
   push @$results, @{$self->_framesStored->{$key}}
      if exists $self->_framesStored->{$key};

   # Add also ICMPv4
   if (exists $self->_framesStored->{ICMPv4}) {
      push @$results, @{$self->_framesStored->{ICMPv4}};
   }

   $results ? @$results : ();
}

sub _dumpFramesStored {
   my $self = shift;
   my ($oSimple) = @_;

   # If parameter, we store it
   if ($oSimple) {
      my $key = $oSimple->getKey;
      push @{$self->_framesStored->{$key}}, $oSimple;

      # If it is ICMPv4, we store a second time
      if (exists $oSimple->ref->{ICMPv4}) {
         push @{$self->_framesStored->{$oSimple->ref->{ICMPv4}->getKey}},
            $oSimple;
      }
   }

   # We return the hash ref
   $self->_framesStored;
}

1;

__END__

=head1 NAME

Net::Frame::Dump - tcpdump like implementation

=head1 DESCRIPTION

B<Net::Frame::Dump> is the base class for all dump modules. With them, you can open a device for live capture, for offline analysis, or for creating a pcap file.

See B<Net::Frame::Dump::Offline>, B<Net::Frame::Dump::Online>, B<Net::Frame::Dump::Writer> for specific usage.

=head1 CONSTANTS

Load them: use Net::Frame::Dump qw(:consts);

=over 4

=item B<NF_DUMP_LAYER_NULL>

=item B<NF_DUMP_LAYER_ETH>

=item B<NF_DUMP_LAYER_RAW>

=item B<NF_DUMP_LAYER_SLL>

=item B<NF_DUMP_LAYER_PPP>

=item B<NF_DUMP_LAYER_80211RADIO>

Various supported link layers.

=back

=head1 SEE ALSO

L<Net::Frame::Dump::Online>, L<Net::Frame::Dump::Offline>, L<Net::Frame::Dump::Writer>

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2006-2008, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut
