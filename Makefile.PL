#
# $Id: Makefile.PL,v 1.3 2006/12/03 16:21:54 gomor Exp $
#
use ExtUtils::MakeMaker;

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
