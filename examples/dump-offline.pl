#!/usr/bin/perl
use strict;
use warnings;

use Net::Frame::Dump qw(:consts);
use Net::Frame::Simple;

my $d = Net::Frame::Dump->new(
   dev  => 'non',
   mode => NP_DUMP_MODE_OFFLINE,
   file => $ARGV[0],
   overwrite     => 0,
   unlinkOnClean => 0,
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
