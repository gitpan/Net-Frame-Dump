#
# $Id: Writer.pm 328 2011-01-13 10:19:33Z gomor $
#
package Net::Frame::Dump::Writer;
use strict;
use warnings;

use Net::Frame::Dump qw(:consts);
our @ISA = qw(Net::Frame::Dump);
__PACKAGE__->cgBuildIndices;

no strict 'vars';

use Carp;
use Net::Pcap;

sub new {
   shift->_dumpNew(
      firstLayer => 'RAW',
      @_,
   );
}

my $mapLinks = {
   NULL => NF_DUMP_LAYER_NULL(),
   ETH  => NF_DUMP_LAYER_ETH(),
   RAW  => NF_DUMP_LAYER_RAW(),
   SLL  => NF_DUMP_LAYER_SLL(),
   PPP  => NF_DUMP_LAYER_PPP(),
};

sub _getPcapHeader {
   my $self = shift;

   my $val = $mapLinks->{$self->[$__firstLayer]} or do {
      warn("Can't get pcap header information for this layer type\n");
      return;
   };

   # 24 bytes header
   "\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00".
   "\x00\x00\x00\x00\xdc\x05\x00\x00".
   pack('C', $val).
   "\x00\x00\x00";
}

sub _openFile {
   my $self = shift;

   my $file = $self->[$__file];
   my $hdr  = $self->_getPcapHeader;
   open(my $fh, '>', $file) or do {
      warn("@{[(caller(0))[3]]}: open: $file: $!\n");
      return;
   };
   syswrite($fh, $hdr, length($hdr));
   close($fh);

   my $err;
   my $pcapd = Net::Pcap::open_offline($file, \$err);
   unless ($pcapd) {
      warn("@{[(caller(0))[3]]}: Net::Pcap::open_offline: ".
           "$file: $err\n");
      return;
   }
   $self->[$___pcapd] = $pcapd;

   $self->[$___dumper] = Net::Pcap::dump_open($pcapd, $file);
   unless ($self->[$___dumper]) {
      warn("@{[(caller(0))[3]]}: Net::Pcap::dump_open: ".
           Net::Pcap::geterr($pcapd)."\n");
      return;
   }

   return 1;
}

sub start {
   my $self = shift;

   $self->[$__isRunning] = 1;

   if (-f $self->[$__file] && ! $self->[$__overwrite]) {
      warn("We will not overwrite a file by default. Use `overwrite' ".
           "attribute to do it\n");
      return;
   }

   $self->_openFile;

   return 1;
}

sub stop {
   my $self = shift;

   return unless $self->[$__isRunning];

   Net::Pcap::dump_close($self->[$___dumper]);

   Net::Pcap::close($self->[$___pcapd]);
   $self->[$__isRunning] = 0;

   return 1;
}

sub write {
   my $self = shift;
   my ($h) = @_;

   my $len = length($h->{raw});

   # Create pcap header
   my ($sec, $usec) = split('\.', $h->{timestamp});
   my $hdr = {
      len     => $len,
      caplen  => $len,
      tv_sec  => $sec,
      tv_usec => $usec,
   };

   Net::Pcap::pcap_dump($self->[$___dumper], $hdr, $h->{raw});
   Net::Pcap::dump_flush($self->[$___dumper]);
}

1;

__END__

=head1 NAME

Net::Frame::Dump::Writer - tcpdump like implementation, writer mode

=head1 SYNOPSIS

   use Net::Frame::Dump::Writer;

   my $oDump = Net::Frame::Dump::Writer->new(
      file       => 'new-file.pcap',
      firstLayer => 'ETH',
   );

   $oDump->start;

   $oDump->write({ timestamp => '10.10', raw => ('A' x 14) });

   $oDump->stop;

=head1 DESCRIPTION

This module implements a pcap file builder. You will be able to create frames, then write them in the pcap file format to a file.

=head1 ATTRIBUTES

The following are inherited attributes:

=over 4

=item B<file>

Name of the .pcap file to generate.

=item B<overwrite>

Overwrites a .pcap file that already exists. Default to not.

=item B<firstLayer>

Stores information about the first layer type. It is used to write .pcap file header information.

=item B<isRunning>

Returns true if a call to B<start> has been done, false otherwise or if a call to B<stop> has been done.

=back

=head1 METHODS

=over 4

=item B<new>

=item B<new> (hash)

Object constructor. You can pass attributes that will overwrite default ones. See B<SYNOPSIS> for default values.

=item B<start>

When you want to start writing frames to the file, call this method.

=item B<stop>

When you want to stop writing frames to the file, call this method.

=item B<write> ({ timestamp => $value, raw => $rawFrame })

Takes a hashref as a parameter. This hashref MUST have timestamp and raw keys, with values. The raw data will be stored to the .pcap file.

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
