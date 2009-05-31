#
# $Id: Makefile.PL 312 2009-05-31 14:45:13Z gomor $
#
use ExtUtils::MakeMaker;

require v5.6.1;

WriteMakefile(
   NAME          => 'Net::Frame::Dump',
   VERSION_FROM  => 'lib/Net/Frame/Dump.pm',
   LICENSE       => 'artistic',
   ABSTRACT_FROM => 'lib/Net/Frame/Dump.pm',
   AUTHOR        => 'GomoR <gomor-cpan_at_gomor.org>',
   PREREQ_PM     => {
      Class::Gomor => '1.00',
      Net::Pcap    => '0.12',
      Net::Frame   => 0,
      Time::HiRes  => 0,
   },
);
