#
# $Id: Makefile.PL,v 1.4 2006/12/14 17:48:40 gomor Exp $
#
use ExtUtils::MakeMaker;

require v5.6.1;

WriteMakefile(
   NAME          => 'Net::Frame::Dump',
   VERSION_FROM  => 'lib/Net/Frame/Dump.pm',
   LICENSE       => 'Artistic',
   ABSTRACT_FROM => 'lib/Net/Frame/Dump.pm',
   AUTHOR        => 'GomoR <perl@gomor.org>',
   PREREQ_PM     => {
      Class::Gomor => '1.00',
      Net::Pcap    => '0.12',
      Net::Frame   => 0,
      Time::HiRes  => 0,
   },
);
