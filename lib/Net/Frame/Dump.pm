#
# $Id: Dump.pm,v 1.5 2006/12/06 21:14:38 gomor Exp $
#
package Net::Frame::Dump;
use strict;
use warnings;

our $VERSION = '1.00_03';

require Class::Gomor::Array;
require Exporter;
our @ISA = qw(Class::Gomor::Array Exporter);

our %EXPORT_TAGS = (
   consts => [qw(
      NP_DUMP_LINK_NULL
      NP_DUMP_LINK_ETH
      NP_DUMP_LINK_RAW
      NP_DUMP_LINK_SLL
      NP_DUMP_LINK_PPP
   )],
);
our @EXPORT_OK = (
   @{$EXPORT_TAGS{consts}},
);

use constant NP_DUMP_LINK_NULL    => 0;
use constant NP_DUMP_LINK_ETH     => 1;
use constant NP_DUMP_LINK_PPP     => 9;
use constant NP_DUMP_LINK_RAW     => 12;
use constant NP_DUMP_LINK_SLL     => 113;

our @AS = qw(
   file
   filter
   overwrite
   link
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
use Net::Frame::Utils qw(getRandom32bitsInt);

sub new {
   my $int = getRandom32bitsInt();
   shift->SUPER::new(
      file          => "netframe-tmp-$$.$int.pcap",
      filter        => '',
      overwrite     => 0,
      isRunning     => 0,
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
   NP_DUMP_LINK_NULL() => 'NULL',
   NP_DUMP_LINK_ETH()  => 'ETH',
   NP_DUMP_LINK_RAW()  => 'RAW',
   NP_DUMP_LINK_SLL()  => 'SLL',
   NP_DUMP_LINK_PPP()  => 'PPP',
};

sub _dumpPcapNext {
   my $self = shift;

   my %hdr;
   if (my $raw = Net::Pcap::next($self->_pcapd, \%hdr)) {
      my $ts = $self->keepTimestamp ? $self->_getTimestamp(\%hdr)
                                    : $self->_setTimestamp;
      return {
         firstLayer => $mapLinks->{$self->link} || 'UNKNOWN',
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

Net::Frame::Dump - tcpdump like implementation, base class only

=head1 SYNOPSIS

=head1 DESCRIPTION

=head1 ATTRIBUTES

=over 4

=back

=head1 METHODS

=over 4

=item B<new>

=back

=head1 CONSTANTS

=over 4

=back

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2006, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut
