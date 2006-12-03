#!/usr/bin/perl
use strict;
use warnings;

use Net::Frame::IPv4;
use Net::Frame::Dump qw(:consts);
use Net::Frame::Simple;

my $d = Net::Frame::Dump->new(
   dev  => 'non',
   mode => NP_DUMP_MODE_WRITER,
   file => 'new-file.pcap',
   overwrite     => 0,
   unlinkOnClean => 0,
);

$d->start;

for (0..255) {
   my $ip = Net::Frame::IPv4->new(
      length   => 1480,
      protocol => $_,
   );
   $ip->pack;
   my $raw = pack('H*', 'f'x1000);
   $d->write({ timestamp => '10.10', raw => $ip->raw.$raw });
}

$d->stop;
$d->clean;
