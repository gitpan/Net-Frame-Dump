#
# $Id: Writer.pm,v 1.4 2006/12/14 17:50:20 gomor Exp $
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
   shift->SUPER::new(
      firstLayer => NF_DUMP_LAYER_RAW,
      @_,
   );
}

sub _getPcapHeader {
   my $self = shift;
   # 24 bytes header
   "\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00".
   "\x00\x00\x00\x00\xdc\x05\x00\x00".
   pack('C', $self->[$__firstLayer]).
   "\x00\x00\x00";
}

sub _openFile {
   my $self = shift;

   my $file = $self->[$__file];
   my $hdr  = $self->_getPcapHeader;
   open(my $fh, '>', $file)
      or croak("@{[(caller(0))[3]]}: open: $file: $!\n");
   syswrite($fh, $hdr, length($hdr));
   close($fh);

   my $err;
   my $pcapd = Net::Pcap::open_offline($file, \$err);
   unless ($pcapd) {
      croak("@{[(caller(0))[3]]}: Net::Pcap::open_offline: ".
            "$file: $err\n");
   }
   $self->[$___pcapd] = $pcapd;

   $self->[$___dumper] = Net::Pcap::dump_open($pcapd, $file);
   unless ($self->[$___dumper]) {
      croak("@{[(caller(0))[3]]}: Net::Pcap::dump_open: ".
            Net::Pcap::geterr($pcapd)."\n");
   }

   1;
}

sub start {
   my $self = shift;

   $self->[$__isRunning] = 1;

   if (-f $self->[$__file] && ! $self->[$__overwrite]) {
      croak("We will not overwrite a file by default. Use `overwrite' ".
            "attribute to do it\n");
   }

   $self->_openFile;

   1;
}

sub stop {
   my $self = shift;

   return unless $self->[$__isRunning];

   Net::Pcap::dump_close($self->[$___dumper]);

   Net::Pcap::close($self->[$___pcapd]);
   $self->[$__isRunning] = 0;

   1;
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

=head1 DESCRIPTION

=head1 ATTRIBUTES

=over 4

=back

=head1 METHODS

=over 4

=item B<new>

=item B<start>

=item B<stop>

=item B<write>

=back

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2006, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut
