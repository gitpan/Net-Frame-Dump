#!/usr/bin/perl
use strict;
use warnings;

my $oDump;
my $dev = shift || die("Specify network interface to use\n");

use Net::Frame::Dump::Online2;
use Net::Frame::Simple;
use Class::Gomor qw($Debug);
$Debug = 3;

$oDump = Net::Frame::Dump::Online2->new(
   dev => $dev,
);
$oDump->start;

while (1) {
   if (my $f = $oDump->next) {
      my $raw            = $f->{raw};
      my $firstLayerType = $f->{firstLayer};
      my $timestamp      = $f->{timestamp};
      print "Received at: $timestamp\n";
   }
}
