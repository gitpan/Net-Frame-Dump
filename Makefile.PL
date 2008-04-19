#
# $Id: Makefile.PL 101 2008-02-17 12:36:50Z gomor $
#
use ExtUtils::MakeMaker;

require v5.6.1;

WriteMakefile(
   NAME          => 'Net::Frame::Dump',
   VERSION_FROM  => 'lib/Net/Frame/Dump.pm',
   LICENSE       => 'artistic',
   ABSTRACT_FROM => 'lib/Net/Frame/Dump.pm',
   AUTHOR        => 'GomoR <perl@gomor.org>',
   PREREQ_PM     => {
      Class::Gomor => '1.00',
      Net::Pcap    => '0.12',
      Net::Frame   => 0,
      Time::HiRes  => 0,
   },
);
