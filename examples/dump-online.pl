#!/usr/bin/perl
use strict;
use warnings;

use Net::Frame::Dump qw(:consts);
use Net::Frame::Simple;

my $d = Net::Frame::Dump->new(
   dev  => $ARGV[0],
   mode => NP_DUMP_MODE_ONLINE,
);

$d->start;

my $count = 0;
while (1) {
   if (my $h = $d->next) {
      my $f = Net::Frame::Simple->new(
         raw        => $h->{raw},
         firstLayer => $h->{firstLayer},
         timestamp  => $h->{timestamp},
      );
      my $len = length($h->{raw});
      print 'o Frame number: '.$count++." (length: $len)\n";
      print $f->print."\n";
   }
}

$d->stop;
$d->clean;

END {
   if ($d && $d->isRunning) {
      $d->stop;
      $d->clean;
   }
}
