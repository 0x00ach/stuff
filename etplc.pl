#!/usr/bin/perl

# changelog:
# 13fev2014: new -c cmd line option (category)
# 17jan2014: new -d cmd line option (debug)
# 31dec2013: added gzip signatures support
# 21nov2013: rewrite http_cookie
#  9nov2013: added fast_pattern
#  2nov2013: rewrite with hash
# 16Oct2013: print proxy_hostname_ip + client_hostname_ip + client_username
# 12Oct2013: rewrite for https/ssl-tunnel and bluecoat
# 24Sep2013: change fork to perl threads queue
#  2Sep2013: add @argv -s syslog like + usage + cpuinfo + adding new fast_pattern
#  1Sep2013: rewrite User-Agent
# 25Aug2013: rewrite for referer
# 24Aug2013: rewrite for case sensitive
#  6Aug2013: add ^

use strict;
use warnings;
use IO::Socket::INET;
use URI::Escape;

# sudo aptitude install libstring-escape-perl # ubuntu
# sudo aptitude install liburi-perl # ubuntu
# sudo yum install perl-String-Escape # fedora
use String::Escape qw( printable unprintable );

use threads;
use Thread::Queue;

# on ubuntu, need manualy install since http://search.cpan.org/CPAN/authors/id/N/NW/NWCLARK/PerlIO-gzip-0.18.tar.gz and package zlib1g-dev
# sudo yum install perl-PerlIO-gzip # fedora
use PerlIO::gzip;

my $recieved_data;

my ($timestamp_central,$proxy_hostname_ip,$timestamp_unix,$client_hostname_ip,$client_username,$proxy_http_reply_code,$client_http_method,$client_http_uri,$web_hostname_ip,$client_http_useragent,$client_http_referer,$client_http_cookie);

my $debug1=0;
my $debug2=0;
my $output_escape;
my @fileemergingthreats;
my @tableauuricontent;
my @tableauuseragent;
my @tableauhttpmethod;
my $max_procs=0;
my %hash;
my $etmsg;
my $clef;
my $clef2;
my $category='\S+';

my $syslogsock;
my $syslogip="127.0.0.1";
my $syslogport="514";
my $syslogproto="udp";

# A new empty queue
my $queue = Thread::Queue->new();

# flush after every write
$| = 1;

if( -t STDIN )
{
 print "==================================================\n";
 print "ETPLC (Emerging Threats Proxy Logs Checker)\n";
 print "Check your Proxy or WebServer Logs with Emerging Threats Community Ruleset.\n";
 print "http://etplc.org - Twitter: \@Rmkml\n";
 print "\n";
 print "Example: tail -f /var/log/messages | perl etplc.pl -f abc.rules.gz\n";
 print "For enable optional syslog, add -s on command line\n";
 print "For enable optional debugging, add -d on command line\n";
 print "For enable optional category, add -c all|proxy|webserver on command line\n";
 print "==================================================\n";
 exit;
}

if( @ARGV == 1 )
{
 print "exit, you must need more than one argument\n";
 exit;
}
elsif( @ARGV == 2 )
{
 if( $ARGV[0] eq "-f" )
 {
  if( $ARGV[1] =~ /\.gz$/ ) { open FILEEMERGINGTHREATS, "<:gzip", $ARGV[1] or die $!; }
  else { open FILEEMERGINGTHREATS, $ARGV[1] or die $!; }
  push(@fileemergingthreats, <FILEEMERGINGTHREATS>);
  close FILEEMERGINGTHREATS;
 }
 else
 {
  print "exit, wrong argument\n";
  exit;
 }
}
elsif( @ARGV == 3 )
{
 if( ($ARGV[0] eq "-s") && ($ARGV[1] eq "-f") )
 {
  $syslogsock = new IO::Socket::INET(PeerAddr=>$syslogip,PeerPort=>$syslogport,Proto=>$syslogproto); die "Syslog Socket could not be created on $syslogproto $syslogip:$syslogport: $!\n" unless $syslogsock;
  if( $ARGV[2] =~ /\.gz$/ ) { open FILEEMERGINGTHREATS, "<:gzip", $ARGV[2] or die $!; }
  else { open FILEEMERGINGTHREATS, $ARGV[2] or die $!; }
  push(@fileemergingthreats, <FILEEMERGINGTHREATS>);
  close FILEEMERGINGTHREATS;
 }
 elsif( ($ARGV[0] eq "-f") && ($ARGV[2] eq "-s") )
 {
  $syslogsock = new IO::Socket::INET(PeerAddr=>$syslogip,PeerPort=>$syslogport,Proto=>$syslogproto); die "Syslog Socket could not be created on $syslogproto $syslogip:$syslogport: $!\n" unless $syslogsock;
  if( $ARGV[1] =~ /\.gz$/ ) { open FILEEMERGINGTHREATS, "<:gzip", $ARGV[1] or die $!; }
  else { open FILEEMERGINGTHREATS, $ARGV[1] or die $!; }
  push(@fileemergingthreats, <FILEEMERGINGTHREATS>);
  close FILEEMERGINGTHREATS;
 }
 elsif( ($ARGV[0] eq "-d") && ($ARGV[1] eq "-f") )
 {
  $syslogsock = new IO::Socket::INET(PeerAddr=>$syslogip,PeerPort=>$syslogport,Proto=>$syslogproto); die "Syslog Socket could not be created on $syslogproto $syslogip:$syslogport: $!\n" unless $syslogsock;
  $debug1=1;
  $debug2=1;
  if( $ARGV[2] =~ /\.gz$/ ) { open FILEEMERGINGTHREATS, "<:gzip", $ARGV[2] or die $!; }
  else { open FILEEMERGINGTHREATS, $ARGV[2] or die $!; }
  push(@fileemergingthreats, <FILEEMERGINGTHREATS>);
  close FILEEMERGINGTHREATS;
 }
 elsif( ($ARGV[0] eq "-f") && ($ARGV[2] eq "-d") )
 {
  $syslogsock = new IO::Socket::INET(PeerAddr=>$syslogip,PeerPort=>$syslogport,Proto=>$syslogproto); die "Syslog Socket could not be created on $syslogproto $syslogip:$syslogport: $!\n" unless $syslogsock;
  $debug1=1;
  $debug2=1;
  if( $ARGV[1] =~ /\.gz$/ ) { open FILEEMERGINGTHREATS, "<:gzip", $ARGV[1] or die $!; }
  else { open FILEEMERGINGTHREATS, $ARGV[1] or die $!; }
  push(@fileemergingthreats, <FILEEMERGINGTHREATS>);
  close FILEEMERGINGTHREATS;
 }
 else
 {
  print "exit, wrong argument\n";
  exit;
 }
}
elsif( @ARGV == 4 )
{
 if( ($ARGV[0] eq "-s") && ($ARGV[1] eq "-d") && ($ARGV[2] eq "-f") )
 {
  $syslogsock = new IO::Socket::INET(PeerAddr=>$syslogip,PeerPort=>$syslogport,Proto=>$syslogproto); die "Syslog Socket could not be created on $syslogproto $syslogip:$syslogport: $!\n" unless $syslogsock;
  $debug1=1;
  $debug2=1;
  if( $ARGV[3] =~ /\.gz$/ ) { open FILEEMERGINGTHREATS, "<:gzip", $ARGV[3] or die $!; }
  else { open FILEEMERGINGTHREATS, $ARGV[3] or die $!; }
  push(@fileemergingthreats, <FILEEMERGINGTHREATS>);
  close FILEEMERGINGTHREATS;
 }
 elsif( ($ARGV[0] eq "-d") && ($ARGV[1] eq "-s") && ($ARGV[2] eq "-f") )
 {
  $syslogsock = new IO::Socket::INET(PeerAddr=>$syslogip,PeerPort=>$syslogport,Proto=>$syslogproto); die "Syslog Socket could not be created on $syslogproto $syslogip:$syslogport: $!\n" unless $syslogsock;
  $debug1=1;
  $debug2=1;
  if( $ARGV[3] =~ /\.gz$/ ) { open FILEEMERGINGTHREATS, "<:gzip", $ARGV[3] or die $!; }
  else { open FILEEMERGINGTHREATS, $ARGV[3] or die $!; }
  push(@fileemergingthreats, <FILEEMERGINGTHREATS>);
  close FILEEMERGINGTHREATS;
 }
 elsif( ($ARGV[0] eq "-f") && ($ARGV[2] eq "-s") && ($ARGV[3] eq "-d") )
 {
  $syslogsock = new IO::Socket::INET(PeerAddr=>$syslogip,PeerPort=>$syslogport,Proto=>$syslogproto); die "Syslog Socket could not be created on $syslogproto $syslogip:$syslogport: $!\n" unless $syslogsock;
  $debug1=1;
  $debug2=1;
  if( $ARGV[1] =~ /\.gz$/ ) { open FILEEMERGINGTHREATS, "<:gzip", $ARGV[1] or die $!; }
  else { open FILEEMERGINGTHREATS, $ARGV[1] or die $!; }
  push(@fileemergingthreats, <FILEEMERGINGTHREATS>);
  close FILEEMERGINGTHREATS;
 }
 elsif( ($ARGV[0] eq "-f") && ($ARGV[2] eq "-d") && ($ARGV[3] eq "-s") )
 {
  $syslogsock = new IO::Socket::INET(PeerAddr=>$syslogip,PeerPort=>$syslogport,Proto=>$syslogproto); die "Syslog Socket could not be created on $syslogproto $syslogip:$syslogport: $!\n" unless $syslogsock;
  $debug1=1;
  $debug2=1;
  if( $ARGV[1] =~ /\.gz$/ ) { open FILEEMERGINGTHREATS, "<:gzip", $ARGV[1] or die $!; }
  else { open FILEEMERGINGTHREATS, $ARGV[1] or die $!; }
  push(@fileemergingthreats, <FILEEMERGINGTHREATS>);
  close FILEEMERGINGTHREATS;
 }
 elsif( ($ARGV[0] eq "-s") && ($ARGV[1] eq "-f") && ($ARGV[3] eq "-d") )
 {
  $syslogsock = new IO::Socket::INET(PeerAddr=>$syslogip,PeerPort=>$syslogport,Proto=>$syslogproto); die "Syslog Socket could not be created on $syslogproto $syslogip:$syslogport: $!\n" unless $syslogsock;
  $debug1=1;
  $debug2=1;
  if( $ARGV[2] =~ /\.gz$/ ) { open FILEEMERGINGTHREATS, "<:gzip", $ARGV[2] or die $!; }
  else { open FILEEMERGINGTHREATS, $ARGV[2] or die $!; }
  push(@fileemergingthreats, <FILEEMERGINGTHREATS>);
  close FILEEMERGINGTHREATS;
 }
 elsif( ($ARGV[0] eq "-d") && ($ARGV[1] eq "-f") && ($ARGV[3] eq "-s") )
 {
  $syslogsock = new IO::Socket::INET(PeerAddr=>$syslogip,PeerPort=>$syslogport,Proto=>$syslogproto); die "Syslog Socket could not be created on $syslogproto $syslogip:$syslogport: $!\n" unless $syslogsock;
  $debug1=1;
  $debug2=1;
  if( $ARGV[2] =~ /\.gz$/ ) { open FILEEMERGINGTHREATS, "<:gzip", $ARGV[2] or die $!; }
  else { open FILEEMERGINGTHREATS, $ARGV[2] or die $!; }
  push(@fileemergingthreats, <FILEEMERGINGTHREATS>);
  close FILEEMERGINGTHREATS;
 }

 elsif( ($ARGV[0] eq "-f") && ($ARGV[2] eq "-c") )
 {
  if( $ARGV[1] =~ /\.gz$/ ) { open FILEEMERGINGTHREATS, "<:gzip", $ARGV[1] or die $!; }
  else { open FILEEMERGINGTHREATS, $ARGV[1] or die $!; }
  push(@fileemergingthreats, <FILEEMERGINGTHREATS>);
  close FILEEMERGINGTHREATS;
  if( $ARGV[3] =~ /^(?:any|proxy|webserver)$/i )
  {
   $category = '(?:\$HTTP_SERVERS|\$HOME_NET)' if $ARGV[3]=~/^webserver$/i;
   $category = '(?:\$EXTERNAL_NET|any|8\.8\.8\.8|209\.139\.208\.0\/23)'     if $ARGV[3]=~/^proxy$/i;
  }
  else
  {
   print "You choose wrong Category on ETPLC, please use any or proxy or webserver (without category use default any)\n";
   exit;
  }
 }
 elsif( ($ARGV[0] eq "-c") && ($ARGV[2] eq "-f") )
 {
  if( $ARGV[3] =~ /\.gz$/ ) { open FILEEMERGINGTHREATS, "<:gzip", $ARGV[3] or die $!; }
  else { open FILEEMERGINGTHREATS, $ARGV[3] or die $!; }
  push(@fileemergingthreats, <FILEEMERGINGTHREATS>);
  close FILEEMERGINGTHREATS;
  if( $ARGV[1] =~ /^(?:any|proxy|webserver)$/i )
  {
   $category = '(?:\$HTTP_SERVERS|\$HOME_NET)' if $ARGV[3]=~/^webserver$/i;
   $category = '(?:\$EXTERNAL_NET|any|8\.8\.8\.8|209\.139\.208\.0\/23)'     if $ARGV[3]=~/^proxy$/i;
  }
  else
  {
   print "You choose wrong Category on ETPLC, please use any or proxy or webserver (without category use default any)\n";
   exit;
  }
 }
 else
 {
  print "exit, wrong argument\n";
  exit;
 }
}
elsif( @ARGV == 5 )
{
 if( ($ARGV[0] eq "-f") && ($ARGV[2] eq "-c") && ($ARGV[4] eq "-s") )
 {
  $syslogsock = new IO::Socket::INET(PeerAddr=>$syslogip,PeerPort=>$syslogport,Proto=>$syslogproto); die "Syslog Socket could not be created on $syslogproto $syslogip:$syslogport: $!\n" unless $syslogsock;
  if( $ARGV[1] =~ /\.gz$/ ) { open FILEEMERGINGTHREATS, "<:gzip", $ARGV[1] or die $!; }
  else { open FILEEMERGINGTHREATS, $ARGV[1] or die $!; }
  push(@fileemergingthreats, <FILEEMERGINGTHREATS>);
  close FILEEMERGINGTHREATS;
  if( $ARGV[3] =~ /^(?:any|proxy|webserver)$/i )
  {
   $category = '(?:\$HTTP_SERVERS|\$HOME_NET)' if $ARGV[3]=~/^webserver$/i;
   $category = '(?:\$EXTERNAL_NET|any|8\.8\.8\.8|209\.139\.208\.0\/23)'     if $ARGV[3]=~/^proxy$/i;
  }
  else
  {
   print "You choose wrong Category on ETPLC, please use any or proxy or webserver (without category use default any)\n";
   exit;
  }
 }
 elsif( ($ARGV[0] eq "-c") && ($ARGV[2] eq "-f") && ($ARGV[4] eq "-s") )
 {
  $syslogsock = new IO::Socket::INET(PeerAddr=>$syslogip,PeerPort=>$syslogport,Proto=>$syslogproto); die "Syslog Socket could not be created on $syslogproto $syslogip:$syslogport: $!\n" unless $syslogsock;
  if( $ARGV[3] =~ /\.gz$/ ) { open FILEEMERGINGTHREATS, "<:gzip", $ARGV[3] or die $!; }
  else { open FILEEMERGINGTHREATS, $ARGV[3] or die $!; }
  push(@fileemergingthreats, <FILEEMERGINGTHREATS>);
  close FILEEMERGINGTHREATS;
  if( $ARGV[1] =~ /^(?:any|proxy|webserver)$/i )
  {
   $category = '(?:\$HTTP_SERVERS|\$HOME_NET)' if $ARGV[3]=~/^webserver$/i;
   $category = '(?:\$EXTERNAL_NET|any|8\.8\.8\.8|209\.139\.208\.0\/23)'     if $ARGV[3]=~/^proxy$/i;
  }
  else
  {
   print "You choose wrong Category on ETPLC, please use any or proxy or webserver (without category use default any)\n";
   exit;
  }
 }
 elsif( ($ARGV[0] eq "-s") && ($ARGV[1] eq "-f") && ($ARGV[3] eq "-c") )
 {
  $syslogsock = new IO::Socket::INET(PeerAddr=>$syslogip,PeerPort=>$syslogport,Proto=>$syslogproto); die "Syslog Socket could not be created on $syslogproto $syslogip:$syslogport: $!\n" unless $syslogsock;
  if( $ARGV[2] =~ /\.gz$/ ) { open FILEEMERGINGTHREATS, "<:gzip", $ARGV[2] or die $!; }
  else { open FILEEMERGINGTHREATS, $ARGV[2] or die $!; }
  push(@fileemergingthreats, <FILEEMERGINGTHREATS>);
  close FILEEMERGINGTHREATS;
  if( $ARGV[4] =~ /^(?:any|proxy|webserver)$/i )
  {
   $category = '(?:\$HTTP_SERVERS|\$HOME_NET)' if $ARGV[3]=~/^webserver$/i;
   $category = '(?:\$EXTERNAL_NET|any|8\.8\.8\.8|209\.139\.208\.0\/23)'     if $ARGV[3]=~/^proxy$/i;
  }
  else
  {
   print "You choose wrong Category on ETPLC, please use any or proxy or webserver (without category use default any)\n";
   exit;
  }
 }
 elsif( ($ARGV[0] eq "-s") && ($ARGV[1] eq "-c") && ($ARGV[3] eq "-f") )
 {
  $syslogsock = new IO::Socket::INET(PeerAddr=>$syslogip,PeerPort=>$syslogport,Proto=>$syslogproto); die "Syslog Socket could not be created on $syslogproto $syslogip:$syslogport: $!\n" unless $syslogsock;
  if( $ARGV[4] =~ /\.gz$/ ) { open FILEEMERGINGTHREATS, "<:gzip", $ARGV[4] or die $!; }
  else { open FILEEMERGINGTHREATS, $ARGV[4] or die $!; }
  push(@fileemergingthreats, <FILEEMERGINGTHREATS>);
  close FILEEMERGINGTHREATS;
  if( $ARGV[2] =~ /^(?:any|proxy|webserver)$/i )
  {
   $category = '(?:\$HTTP_SERVERS|\$HOME_NET)' if $ARGV[3]=~/^webserver$/i;
   $category = '(?:\$EXTERNAL_NET|any|8\.8\.8\.8|209\.139\.208\.0\/23)'     if $ARGV[3]=~/^proxy$/i;
  }
  else
  {
   print "You choose wrong Category on ETPLC, please use any or proxy or webserver (without category use default any)\n";
   exit;
  }
 }
 elsif( ($ARGV[0] eq "-f") && ($ARGV[2] eq "-s") && ($ARGV[3] eq "-c") )
 {
  $syslogsock = new IO::Socket::INET(PeerAddr=>$syslogip,PeerPort=>$syslogport,Proto=>$syslogproto); die "Syslog Socket could not be created on $syslogproto $syslogip:$syslogport: $!\n" unless $syslogsock;
  if( $ARGV[1] =~ /\.gz$/ ) { open FILEEMERGINGTHREATS, "<:gzip", $ARGV[1] or die $!; }
  else { open FILEEMERGINGTHREATS, $ARGV[1] or die $!; }
  push(@fileemergingthreats, <FILEEMERGINGTHREATS>);
  close FILEEMERGINGTHREATS;
  if( $ARGV[4] =~ /^(?:any|proxy|webserver)$/i )
  {
   $category = '(?:\$HTTP_SERVERS|\$HOME_NET)' if $ARGV[3]=~/^webserver$/i;
   $category = '(?:\$EXTERNAL_NET|any|8\.8\.8\.8|209\.139\.208\.0\/23)'     if $ARGV[3]=~/^proxy$/i;
  }
  else
  {
   print "You choose wrong Category on ETPLC, please use any or proxy or webserver (without category use default any)\n";
   exit;
  }
 }
 elsif( ($ARGV[0] eq "-c") && ($ARGV[2] eq "-s") && ($ARGV[3] eq "-f") )
 {
  $syslogsock = new IO::Socket::INET(PeerAddr=>$syslogip,PeerPort=>$syslogport,Proto=>$syslogproto); die "Syslog Socket could not be created on $syslogproto $syslogip:$syslogport: $!\n" unless $syslogsock;
  if( $ARGV[4] =~ /\.gz$/ ) { open FILEEMERGINGTHREATS, "<:gzip", $ARGV[4] or die $!; }
  else { open FILEEMERGINGTHREATS, $ARGV[4] or die $!; }
  push(@fileemergingthreats, <FILEEMERGINGTHREATS>);
  close FILEEMERGINGTHREATS;
  if( $ARGV[1] =~ /^(?:any|proxy|webserver)$/i )
  {
   $category = '(?:\$HTTP_SERVERS|\$HOME_NET)' if $ARGV[3]=~/^webserver$/i;
   $category = '(?:\$EXTERNAL_NET|any|8\.8\.8\.8|209\.139\.208\.0\/23)'     if $ARGV[3]=~/^proxy$/i;
  }
  else
  {
   print "You choose wrong Category on ETPLC, please use any or proxy or webserver (without category use default any)\n";
   exit;
  }
 }
 elsif( ($ARGV[0] eq "-f") && ($ARGV[2] eq "-c") && ($ARGV[4] eq "-d") )
 {
  $debug1=1;
  $debug2=1;
  if( $ARGV[1] =~ /\.gz$/ ) { open FILEEMERGINGTHREATS, "<:gzip", $ARGV[1] or die $!; }
  else { open FILEEMERGINGTHREATS, $ARGV[1] or die $!; }
  push(@fileemergingthreats, <FILEEMERGINGTHREATS>);
  close FILEEMERGINGTHREATS;
  if( $ARGV[3] =~ /^(?:any|proxy|webserver)$/i )
  {
   $category = '(?:\$HTTP_SERVERS|\$HOME_NET)' if $ARGV[3]=~/^webserver$/i;
   $category = '(?:\$EXTERNAL_NET|any|8\.8\.8\.8|209\.139\.208\.0\/23)'     if $ARGV[3]=~/^proxy$/i;
  }
  else
  {
   print "You choose wrong Category on ETPLC, please use any or proxy or webserver (without category use default any)\n";
   exit;
  }
 }
 elsif( ($ARGV[0] eq "-c") && ($ARGV[2] eq "-f") && ($ARGV[4] eq "-d") )
 {
  $debug1=1;
  $debug2=1;
  if( $ARGV[3] =~ /\.gz$/ ) { open FILEEMERGINGTHREATS, "<:gzip", $ARGV[3] or die $!; }
  else { open FILEEMERGINGTHREATS, $ARGV[3] or die $!; }
  push(@fileemergingthreats, <FILEEMERGINGTHREATS>);
  close FILEEMERGINGTHREATS;
  if( $ARGV[1] =~ /^(?:any|proxy|webserver)$/i )
  {
   $category = '(?:\$HTTP_SERVERS|\$HOME_NET)' if $ARGV[3]=~/^webserver$/i;
   $category = '(?:\$EXTERNAL_NET|any|8\.8\.8\.8|209\.139\.208\.0\/23)'     if $ARGV[3]=~/^proxy$/i;
  }
  else
  {
   print "You choose wrong Category on ETPLC, please use any or proxy or webserver (without category use default any)\n";
   exit;
  }
 }
 elsif( ($ARGV[0] eq "-d") && ($ARGV[1] eq "-f") && ($ARGV[3] eq "-c") )
 {
  $debug1=1;
  $debug2=1;
  if( $ARGV[2] =~ /\.gz$/ ) { open FILEEMERGINGTHREATS, "<:gzip", $ARGV[2] or die $!; }
  else { open FILEEMERGINGTHREATS, $ARGV[2] or die $!; }
  push(@fileemergingthreats, <FILEEMERGINGTHREATS>);
  close FILEEMERGINGTHREATS;
  if( $ARGV[4] =~ /^(?:any|proxy|webserver)$/i )
  {
   $category = '(?:\$HTTP_SERVERS|\$HOME_NET)' if $ARGV[3]=~/^webserver$/i;
   $category = '(?:\$EXTERNAL_NET|any|8\.8\.8\.8|209\.139\.208\.0\/23)'     if $ARGV[3]=~/^proxy$/i;
  }
 }
 elsif( ($ARGV[0] eq "-f") && ($ARGV[2] eq "-d") && ($ARGV[3] eq "-c") )
 {
  $debug1=1;
  $debug2=1;
  if( $ARGV[1] =~ /\.gz$/ ) { open FILEEMERGINGTHREATS, "<:gzip", $ARGV[1] or die $!; }
  else { open FILEEMERGINGTHREATS, $ARGV[1] or die $!; }
  push(@fileemergingthreats, <FILEEMERGINGTHREATS>);
  close FILEEMERGINGTHREATS;
  if( $ARGV[4] =~ /^(?:any|proxy|webserver)$/i )
  {
   $category = '(?:\$HTTP_SERVERS|\$HOME_NET)' if $ARGV[3]=~/^webserver$/i;
   $category = '(?:\$EXTERNAL_NET|any|8\.8\.8\.8|209\.139\.208\.0\/23)'     if $ARGV[3]=~/^proxy$/i;
  }
  else
  {
   print "You choose wrong Category on ETPLC, please use any or proxy or webserver (without category use default any)\n";
   exit;
  }
 }
 elsif( ($ARGV[0] eq "-c") && ($ARGV[2] eq "-d") && ($ARGV[3] eq "-f") )
 {
  $debug1=1;
  $debug2=1;
  if( $ARGV[4] =~ /\.gz$/ ) { open FILEEMERGINGTHREATS, "<:gzip", $ARGV[4] or die $!; }
  else { open FILEEMERGINGTHREATS, $ARGV[4] or die $!; }
  push(@fileemergingthreats, <FILEEMERGINGTHREATS>);
  close FILEEMERGINGTHREATS;
  if( $ARGV[1] =~ /^(?:any|proxy|webserver)$/i )
  {
   $category = '(?:\$HTTP_SERVERS|\$HOME_NET)' if $ARGV[3]=~/^webserver$/i;
   $category = '(?:\$EXTERNAL_NET|any|8\.8\.8\.8|209\.139\.208\.0\/23)'     if $ARGV[3]=~/^proxy$/i;
  }
  else
  {
   print "You choose wrong Category on ETPLC, please use any or proxy or webserver (without category use default any)\n";
   exit;
  }
 }
 else
 {
  print "exit, wrong argument\n";
  exit;
 }
}
elsif( @ARGV == 6 )
{
 if( ($ARGV[0] eq "-f") && ($ARGV[2] eq "-c") && ($ARGV[4] eq "-s") && ($ARGV[5] eq "-d") )
 {
  $syslogsock = new IO::Socket::INET(PeerAddr=>$syslogip,PeerPort=>$syslogport,Proto=>$syslogproto); die "Syslog Socket could not be created on $syslogproto $syslogip:$syslogport: $!\n" unless $syslogsock;
  $debug1=1;
  $debug2=1;
  if( $ARGV[1] =~ /\.gz$/ ) { open FILEEMERGINGTHREATS, "<:gzip", $ARGV[1] or die $!; }
  else { open FILEEMERGINGTHREATS, $ARGV[1] or die $!; }
  push(@fileemergingthreats, <FILEEMERGINGTHREATS>);
  close FILEEMERGINGTHREATS;
  if( $ARGV[3] =~ /^(?:any|proxy|webserver)$/i )
  {
   $category = '(?:\$HTTP_SERVERS|\$HOME_NET)' if $ARGV[3]=~/^webserver$/i;
   $category = '(?:\$EXTERNAL_NET|any|8\.8\.8\.8|209\.139\.208\.0\/23)'     if $ARGV[3]=~/^proxy$/i;
  }
  else
  {
   print "You choose wrong Category on ETPLC, please use any or proxy or webserver (without category use default any)\n";
   exit;
  }
 }
 elsif( ($ARGV[0] eq "-f") && ($ARGV[2] eq "-c") && ($ARGV[4] eq "-d") && ($ARGV[5] eq "-s") )
 {
  $syslogsock = new IO::Socket::INET(PeerAddr=>$syslogip,PeerPort=>$syslogport,Proto=>$syslogproto); die "Syslog Socket could not be created on $syslogproto $syslogip:$syslogport: $!\n" unless $syslogsock;
  $debug1=1;
  $debug2=1;
  if( $ARGV[1] =~ /\.gz$/ ) { open FILEEMERGINGTHREATS, "<:gzip", $ARGV[1] or die $!; }
  else { open FILEEMERGINGTHREATS, $ARGV[1] or die $!; }
  push(@fileemergingthreats, <FILEEMERGINGTHREATS>);
  close FILEEMERGINGTHREATS;
  if( $ARGV[3] =~ /^(?:any|proxy|webserver)$/i )
  {
   $category = '(?:\$HTTP_SERVERS|\$HOME_NET)' if $ARGV[3]=~/^webserver$/i;
   $category = '(?:\$EXTERNAL_NET|any|8\.8\.8\.8|209\.139\.208\.0\/23)'     if $ARGV[3]=~/^proxy$/i;
  }
  else
  {
   print "You choose wrong Category on ETPLC, please use any or proxy or webserver (without category use default any)\n";
   exit;
  }
 }
 elsif( ($ARGV[0] eq "-s") && ($ARGV[1] eq "-f") && ($ARGV[3] eq "-c") && ($ARGV[5] eq "-d") )
 {
  $syslogsock = new IO::Socket::INET(PeerAddr=>$syslogip,PeerPort=>$syslogport,Proto=>$syslogproto); die "Syslog Socket could not be created on $syslogproto $syslogip:$syslogport: $!\n" unless $syslogsock;
  $debug1=1;
  $debug2=1;
  if( $ARGV[2] =~ /\.gz$/ ) { open FILEEMERGINGTHREATS, "<:gzip", $ARGV[2] or die $!; }
  else { open FILEEMERGINGTHREATS, $ARGV[2] or die $!; }
  push(@fileemergingthreats, <FILEEMERGINGTHREATS>);
  close FILEEMERGINGTHREATS;
  if( $ARGV[4] =~ /^(?:any|proxy|webserver)$/i )
  {
   $category = '(?:\$HTTP_SERVERS|\$HOME_NET)' if $ARGV[3]=~/^webserver$/i;
   $category = '(?:\$EXTERNAL_NET|any|8\.8\.8\.8|209\.139\.208\.0\/23)'     if $ARGV[3]=~/^proxy$/i;
  }
  else
  {
   print "You choose wrong Category on ETPLC, please use any or proxy or webserver (without category use default any)\n";
   exit;
  }
 }
 elsif( ($ARGV[0] eq "-d") && ($ARGV[1] eq "-f") && ($ARGV[3] eq "-c") && ($ARGV[5] eq "-s") )
 {
  $syslogsock = new IO::Socket::INET(PeerAddr=>$syslogip,PeerPort=>$syslogport,Proto=>$syslogproto); die "Syslog Socket could not be created on $syslogproto $syslogip:$syslogport: $!\n" unless $syslogsock;
  $debug1=1;
  $debug2=1;
  if( $ARGV[2] =~ /\.gz$/ ) { open FILEEMERGINGTHREATS, "<:gzip", $ARGV[2] or die $!; }
  else { open FILEEMERGINGTHREATS, $ARGV[2] or die $!; }
  push(@fileemergingthreats, <FILEEMERGINGTHREATS>);
  close FILEEMERGINGTHREATS;
  if( $ARGV[4] =~ /^(?:any|proxy|webserver)$/i )
  {
   $category = '(?:\$HTTP_SERVERS|\$HOME_NET)' if $ARGV[3]=~/^webserver$/i;
   $category = '(?:\$EXTERNAL_NET|any|8\.8\.8\.8|209\.139\.208\.0\/23)'     if $ARGV[3]=~/^proxy$/i;
  }
  else
  {
   print "You choose wrong Category on ETPLC, please use any or proxy or webserver (without category use default any)\n";
   exit;
  }
 }
 elsif( ($ARGV[0] eq "-d") && ($ARGV[1] eq "-s") && ($ARGV[2] eq "-f") && ($ARGV[4] eq "-c") )
 {
  $syslogsock = new IO::Socket::INET(PeerAddr=>$syslogip,PeerPort=>$syslogport,Proto=>$syslogproto); die "Syslog Socket could not be created on $syslogproto $syslogip:$syslogport: $!\n" unless $syslogsock;
  $debug1=1;
  $debug2=1;
  if( $ARGV[3] =~ /\.gz$/ ) { open FILEEMERGINGTHREATS, "<:gzip", $ARGV[3] or die $!; }
  else { open FILEEMERGINGTHREATS, $ARGV[3] or die $!; }
  push(@fileemergingthreats, <FILEEMERGINGTHREATS>);
  close FILEEMERGINGTHREATS;
  if( $ARGV[5] =~ /^(?:any|proxy|webserver)$/i )
  {
   $category = '(?:\$HTTP_SERVERS|\$HOME_NET)' if $ARGV[3]=~/^webserver$/i;
   $category = '(?:\$EXTERNAL_NET|any|8\.8\.8\.8|209\.139\.208\.0\/23)'     if $ARGV[3]=~/^proxy$/i;
  }
  else
  {
   print "You choose wrong Category on ETPLC, please use any or proxy or webserver (without category use default any)\n";
   exit;
  }
 }
 elsif( ($ARGV[0] eq "-s") && ($ARGV[1] eq "-d") && ($ARGV[2] eq "-f") && ($ARGV[4] eq "-c") )
 {
  $syslogsock = new IO::Socket::INET(PeerAddr=>$syslogip,PeerPort=>$syslogport,Proto=>$syslogproto); die "Syslog Socket could not be created on $syslogproto $syslogip:$syslogport: $!\n" unless $syslogsock;
  $debug1=1;
  $debug2=1;
  if( $ARGV[3] =~ /\.gz$/ ) { open FILEEMERGINGTHREATS, "<:gzip", $ARGV[3] or die $!; }
  else { open FILEEMERGINGTHREATS, $ARGV[3] or die $!; }
  push(@fileemergingthreats, <FILEEMERGINGTHREATS>);
  close FILEEMERGINGTHREATS; 
  if( $ARGV[5] =~ /^(?:any|proxy|webserver)$/i )
  {
   $category = '(?:\$HTTP_SERVERS|\$HOME_NET)' if $ARGV[3]=~/^webserver$/i;
   $category = '(?:\$EXTERNAL_NET|any|8\.8\.8\.8|209\.139\.208\.0\/23)'     if $ARGV[3]=~/^proxy$/i;
  }
  else
  {
   print "You choose wrong Category on ETPLC, please use any or proxy or webserver (without category use default any)\n";
   exit; 
  }
 }
 elsif( ($ARGV[0] eq "-f") && ($ARGV[2] eq "-s") && ($ARGV[3] eq "-c") && ($ARGV[5] eq "-d") )
 {
  $syslogsock = new IO::Socket::INET(PeerAddr=>$syslogip,PeerPort=>$syslogport,Proto=>$syslogproto); die "Syslog Socket could not be created on $syslogproto $syslogip:$syslogport: $!\n" unless $syslogsock;
  $debug1=1;
  $debug2=1;
  if( $ARGV[1] =~ /\.gz$/ ) { open FILEEMERGINGTHREATS, "<:gzip", $ARGV[1] or die $!; }
  else { open FILEEMERGINGTHREATS, $ARGV[1] or die $!; }
  push(@fileemergingthreats, <FILEEMERGINGTHREATS>);
  close FILEEMERGINGTHREATS;
  if( $ARGV[4] =~ /^(?:any|proxy|webserver)$/i )
  {
   $category = '(?:\$HTTP_SERVERS|\$HOME_NET)' if $ARGV[3]=~/^webserver$/i;
   $category = '(?:\$EXTERNAL_NET|any|8\.8\.8\.8|209\.139\.208\.0\/23)'     if $ARGV[3]=~/^proxy$/i;
  }
  else
  {
   print "You choose wrong Category on ETPLC, please use any or proxy or webserver (without category use default any)\n";
   exit;
  }
 }
 elsif( ($ARGV[0] eq "-f") && ($ARGV[2] eq "-d") && ($ARGV[3] eq "-c") && ($ARGV[5] eq "-s") )
 {
  $syslogsock = new IO::Socket::INET(PeerAddr=>$syslogip,PeerPort=>$syslogport,Proto=>$syslogproto); die "Syslog Socket could not be created on $syslogproto $syslogip:$syslogport: $!\n" unless $syslogsock;
  $debug1=1;
  $debug2=1;
  if( $ARGV[1] =~ /\.gz$/ ) { open FILEEMERGINGTHREATS, "<:gzip", $ARGV[1] or die $!; }
  else { open FILEEMERGINGTHREATS, $ARGV[1] or die $!; }
  push(@fileemergingthreats, <FILEEMERGINGTHREATS>);
  close FILEEMERGINGTHREATS;
  if( $ARGV[4] =~ /^(?:any|proxy|webserver)$/i )
  {
   $category = '(?:\$HTTP_SERVERS|\$HOME_NET)' if $ARGV[3]=~/^webserver$/i;
   $category = '(?:\$EXTERNAL_NET|any|8\.8\.8\.8|209\.139\.208\.0\/23)'     if $ARGV[3]=~/^proxy$/i;
  }
  else
  {
   print "You choose wrong Category on ETPLC, please use any or proxy or webserver (without category use default any)\n";
   exit;
  }
 }
 elsif( ($ARGV[0] eq "-f") && ($ARGV[2] eq "-s") && ($ARGV[3] eq "-d") && ($ARGV[4] eq "-c") )
 {
  $syslogsock = new IO::Socket::INET(PeerAddr=>$syslogip,PeerPort=>$syslogport,Proto=>$syslogproto); die "Syslog Socket could not be created on $syslogproto $syslogip:$syslogport: $!\n" unless $syslogsock;
  $debug1=1;
  $debug2=1;
  if( $ARGV[1] =~ /\.gz$/ ) { open FILEEMERGINGTHREATS, "<:gzip", $ARGV[1] or die $!; }
  else { open FILEEMERGINGTHREATS, $ARGV[1] or die $!; }
  push(@fileemergingthreats, <FILEEMERGINGTHREATS>);
  close FILEEMERGINGTHREATS;
  if( $ARGV[5] =~ /^(?:any|proxy|webserver)$/i )
  {
   $category = '(?:\$HTTP_SERVERS|\$HOME_NET)' if $ARGV[3]=~/^webserver$/i;
   $category = '(?:\$EXTERNAL_NET|any|8\.8\.8\.8|209\.139\.208\.0\/23)'     if $ARGV[3]=~/^proxy$/i;
  }
  else
  {
   print "You choose wrong Category on ETPLC, please use any or proxy or webserver (without category use default any)\n";
   exit;
  }
 }
 elsif( ($ARGV[0] eq "-f") && ($ARGV[2] eq "-d") && ($ARGV[3] eq "-s") && ($ARGV[4] eq "-c") )
 {
  $syslogsock = new IO::Socket::INET(PeerAddr=>$syslogip,PeerPort=>$syslogport,Proto=>$syslogproto); die "Syslog Socket could not be created on $syslogproto $syslogip:$syslogport: $!\n" unless $syslogsock;
  $debug1=1;
  $debug2=1;
  if( $ARGV[1] =~ /\.gz$/ ) { open FILEEMERGINGTHREATS, "<:gzip", $ARGV[1] or die $!; }
  else { open FILEEMERGINGTHREATS, $ARGV[1] or die $!; }
  push(@fileemergingthreats, <FILEEMERGINGTHREATS>);
  close FILEEMERGINGTHREATS;
  if( $ARGV[5] =~ /^(?:any|proxy|webserver)$/i )
  {
   $category = '(?:\$HTTP_SERVERS|\$HOME_NET)' if $ARGV[3]=~/^webserver$/i;
   $category = '(?:\$EXTERNAL_NET|any|8\.8\.8\.8|209\.139\.208\.0\/23)'     if $ARGV[3]=~/^proxy$/i;
  }
  else
  {
   print "You choose wrong Category on ETPLC, please use any or proxy or webserver (without category use default any)\n";
   exit;
  }
 }
 else
 {
  print "exit, wrong argument\n";
  exit;
 }
}
elsif( @ARGV > 6)
{
 print "exit, too many arguments\n";
 exit;
}
else
{
 print "==================================================\n";
 print "ETPLC (Emerging Threats Proxy Logs Checker)\n";
 print "Check your Proxy or WebServer Logs with Emerging Threats Community Ruleset.\n";
 print "http://etplc.org - Twitter: \@Rmkml\n";
 print "\n";
 print "Example: tail -f /var/log/messages | perl etplc.pl -f abc.rules.gz\n";
 print "For enable optional syslog, add -s on command line\n";
 print "For enable optional debugging, add -d on command line\n";
 print "For enable optional category, add -c all|proxy|webserver on command line\n";
 print "==================================================\n";
 exit;
}

if( open(CPUINFO, "/proc/cpuinfo") )
{
 foreach( <CPUINFO> )
 {
  if( /^processor\s+\:\s\d+$/ )
  {
   $max_procs++;
  }
 }
}
else
{
 $max_procs=1;
}
close CPUINFO;

####################################################################################################

 my $urilen1='\s*urilen\:\s*\d*\s*\<?\s*\>?\s*\d+\;';
 my $flowbits1='\s*flowbits\:.*?\;';
 my $flow1='flow\:\s*(?:to_server|to_client|from_client|from_server)?(?:\s*\,)?(?:established)?(?:\s*\,\s*)?(?:to_server|to_client|from_client|from_server)?\;';
 my $httpmethod='\s*content\:\"([gG][eE][tT]|[pP][oO][sS][tT]|[hH][eE][aA][dD]|[sS][eE][aA][rR][cC][hH]|[pP][rR][oO][pP][fF][iI][nN][dD]|[tT][rR][aA][cC][eE]|[oO][pP][tT][iI][oO][nN][sS]|[dD][eE][bB][uU][gG]|[cC][oO][nN][nN][eE][cC][tT]|[dD][eE][lL][eE][tT][eE]|[pP][uU][tT])\s*[^\"]*?\"\;(?:\s*(nocase)\;\s*|\s*http_method\;\s*|\s*depth\:\d+\;\s*)*';
 my $contentoptions1='\s*(fast_pattern)(?:\:only|\:\d+\,\d+)?\;|\s*(nocase)\;|\s*offset\:\d+\;|\s*depth\:\d+\;|\s*distance\:\s*\-?(\d+)\;|\s*within\:(\d+)\;|\s*http_raw_uri\;';
 my $negateuricontent1='\s*(?:uri)?content\:\!\"[^\"]*?\"\s*\;(?:\s*fast_pattern(?:\:only|\d+\,\d+)?\;|\s*nocase\;|\s*http_uri\;|\s*http_header\;|\s*http_cookie\;|\s*offset\:\d+\;|\s*depth\:\d+\;|\s*http_raw_uri\;|\s*distance\:\s*\-?\d+\;|\s*within\:\d+\;|\s*http_client_body\;)*';
 my $extracontentoptions='\s*threshold\:.*?\;|\s*flowbits\:.*?\;|\s*isdataat\:\d+(?:\,relative)?\;|\s*dsize\:[\<\>]*\d+\;|\s*urilen\:\s*\d*\s*\<?\s*\>?\s*\d+\;|\s*detection_filter\:.*?\;|\s*priority\:\d+\;|\s*metadata\:.*?\;';
 my $referencesidrev='(?:\s*reference\:.*?\;\s*)*\s*classtype\:.*?\;\s*sid\:\d+\;\s*rev\:\d+\;\s*\)\s*';
 my $pcreuri='\s*pcre\:\"\/(.*?)\/[smiUGDIR]*\"\;'; # not header/Cookie/Post_payload!
 my $pcreagent='\s*pcre\:\"\/(.*?)\/[smiH]*\"\;';

foreach $_ ( @fileemergingthreats )
{
 chomp($_);
 #print "brut: $_\n" if $debug1;
 if($_=~/^(\#|$)/)
 {
  next;
 }

#alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET WEB_CLIENT Possible Adobe Reader and Acrobat Forms Data Format Remote Security Bypass Attempt"; flow:established,to_client; file_data; content:"%FDF-"; depth:300; content:"/F(JavaScript|3a|"; nocase; distance:0; reference:url,www.securityfocus.com/bid/37763; reference:cve,2009-3956; reference:url,doc.emergingthreats.net/2010664; reference:url,www.stratsec.net/files/SS-2010-001_Stratsec_Acrobat_Script_Injection_Security_Advisory_v1.0.pdf; classtype:attempted-user; sid:2010664; rev:8;)
 elsif( $_=~ /^\s*alert\s+(?:udp|tcp)\s+\S+\s+\S+\s+\-\>\s+\S+\s+\S+\s+\(\s*msg\:\s*\"([^\"]*?)\"\s*\;\s*flow\:\s*(?:to_client\s*\,|from_server\s*\,)?established(?:\s*\,\s*to_client|\s*\,\s*from_server)?\;/ )
 {
  #print "to_client: $_\n" if $debug1;
  next;
 }

#alert icmp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN Overtoolbar.net Backdoor ICMP Checkin Request"; dsize:9; icode:0; itype:8; content:"Echo This"; reference:url,doc.emergingthreats.net/2009130; classtype:trojan-activity; sid:2009130; rev:3;)
#alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"ET POLICY Protocol 41 IPv6 encapsulation potential 6in4 IPv6 tunnel active"; ip_proto:41; threshold:type both,track by_dst, count 1, seconds 60; reference:url,en.wikipedia.org/wiki/6in4; classtype:policy-violation; sid:2012141; rev:2;)
 elsif( $_=~ /^\s*alert\s+(?:icmp|ip)\s+\S+\s+\S+\s+\-\>\s+\S+\s+\S+\s+/ )
 {
  #print "icmp_ip: $_\n" if $debug1;
  next;
 }

#alert tcp $HOME_NET any <> $EXTERNAL_NET any (msg:"ET POLICY ICQ Message"; flow: established; content:"|2A02|"; depth: 2; content:"|000400060000|"; offset: 6; depth: 6; reference:url,doc.emergingthreats.net/2001805; classtype:policy-violation; sid:2001805; rev:5;)
 elsif( $_=~ /^\s*alert\s+(?:udp|tcp)\s+\S+\s+\S+\s+\<\>\s+\S+\s+\S+\s+/ )
 {
  #print "udp_tcp_<_>: $_\n" if $debug1;
  next;
 }

 elsif( $_=~ /\bhttp_client_body\;/ )
 {
  next;
 }

 # begin http_uri
 elsif( $_=~ /^\s*alert\s+(?:udp|tcp)\s+\S+\s+\S+\s+\-\>\s+$category\s+\S+\s+\(\s*msg\:\s*\"([^\"]*?)\"\s*\;\s*(?:$flow1)?(?:$flowbits1)?(?:$urilen1)?(?:$httpmethod)?(?:$urilen1)?(?:$negateuricontent1)?\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*\s*(?:http_uri|http_raw_uri)\;(?:$contentoptions1)*(?:$negateuricontent1)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:\s*http_uri\;)?(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:\s*http_uri\;)?(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:$extracontentoptions)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:\s*http_uri\;)?(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:$extracontentoptions)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:\s*http_uri\;)?(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:$extracontentoptions)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:\s*http_uri\;)?(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:$extracontentoptions)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:\s*http_uri\;)?(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:$extracontentoptions)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:\s*http_uri\;)?(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:$extracontentoptions)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:\s*http_uri\;)?(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:$extracontentoptions)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:\s*http_uri\;)?(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:$extracontentoptions)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:\s*http_uri\;)?(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:$extracontentoptions)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:\s*http_uri\;)?(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:$extracontentoptions)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:\s*http_uri\;)?(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:$extracontentoptions)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*\s*http_header\;(?:$contentoptions1)*(?:$negateuricontent1)?)?(?:$pcreuri)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*\s*http_header\;(?:$contentoptions1)*(?:$negateuricontent1)?)?(?:$pcreagent)?(?:$negateuricontent1)?(?:$extracontentoptions)?$referencesidrev$/ )
 {
  my $etmsg1=$1;
  my $http_method2=0;
  my $http_methodnocase3=0;
  print "brut1: $_\n" if $debug1;
  #print "here1: 1: $1, 2: $2, 3: $3, 4: $4, 5: $5, 6: $6, 7: $7, 8: $8, 9: $9, 10: $10, 11: $11, 12: $12, 13: $13, 14: $14, 15: $15, 16: $16, 17: $17, 18: $18, 19: $19, 20: $20, 21: $21, 22: $22, 23: $23, 24: $24, 25: $25, 26: $26, 27: $27, 28: $28, 29: $29, 30: $30, 31: $31, 32: $32, 33: $33, 34: $34, 35: $35, 36: $36, 37: $37, $38, $39, 40: $40, $41, $42, $43, $44, $45, $46, $47, $48, $49, 50: $50, $51, $52, $53, 54: $54, $55, $56, $57, $58, $59, 60: $60, $61, $62, $63, $64, $65, $66, $67, $68, $69, 70: $70, $71, $72, $73, $74, $75, $76, $77, $78, $79, 80: $80, $81, $82, $83, $84, $85, $86, $87, $88, $89, 90: $90, $91, $92, $93, $94, 95: $95, $96, $97, $98, $99, 100: $100, $101, $102, 103: $103, $104, $105, $106, $107, $108, $109, 110: $110, $111, $112, $113, $114, $115, $116, $117, $118, $119, 120: $120, 121: $121, $122, $123, $124, $125, $126, $127, $128, $129, 130: $130, $131, $132, $133, $134, $135, $136, $137, $138, $139, 140: $140\n" if $debug1;

     $http_method2=$2 if $2;
     $http_methodnocase3=$3 if $3;
  my $http_uri03=$4 if $4;
  my $http_urifast5=$5 if $5;
  my $http_urinocase5=$6 if $6;		# 5
  my $http_urifast9=$9 if $9;
  my $http_uri08=$13 if $13;		# 11
  my $http_urifast14=$14 if $14;
  my $http_urinocase12=$15 if $15;	# 12
  my $distance9=$16 if defined($16);	# 13
  my $distance10=$17 if defined($17);	# 14
  my $http_urifast18=$18 if $18;
  my $http_urinocase15=$19 if $19;	# 15
  my $distance11=$20 if defined($20);	# 16
  my $distance12=$21 if defined($21);	# 17
  my $http_uri13=$22 if $22;		# 18
  my $http_urifast23=$23 if $23;
  my $http_urinocase19=$24 if $24;	# 19
  my $distance14=$25 if defined($25);	# 20
  my $distance15=$26 if defined($26);	# 21
  my $http_urifast27=$27 if $27;
  my $http_urinocase22=$28 if $28;	# 22
  my $distance16=$29 if defined($29);	# 23
  my $distance17=$30 if defined($30);	# 24
  my $http_uri18=$31 if $31;		# 25
  my $http_urifast32=$32 if $32;
  my $http_urinocase26=$33 if $33;	# 26
  my $distance19=$34 if defined($34);	# 27
  my $distance20=$35 if defined($35);	# 28
  my $http_urifast36=$36 if $36;
  my $http_urinocase29=$37 if $37;	# 29
  my $distance21=$38 if defined($38);	# 30
  my $distance22=$39 if defined($39);	# 31
  my $http_uri23=$40 if $40;		# 32
  my $http_urifast41=$41 if $41;
  my $http_urinocase33=$42 if $42;	# 33
  my $distance24=$43 if defined($43);	# 34
  my $distance25=$44 if defined($44);	# 35
  my $http_urifast44=$45 if $45;
  my $http_urinocase36=$46 if $46;	# 36
  my $distance26=$47 if defined($47);	# 37
  my $distance27=$48 if defined($48);	# 38
  my $http_uri28=$49 if $49;		# 39
  my $http_urifast49=$50 if $50;
  my $http_urinocase40=$51 if $51;	# 40
  my $distance29=$52 if defined($52);	# 41
  my $distance30=$53 if defined($53);	# 42
  my $http_urifast54=$54 if $54;
  my $http_urinocase43=$55 if $55;	# 43
  my $distance31=$56 if defined($56);	# 44
  my $distance32=$57 if defined($57);	# 45
  my $http_uri33=$58 if $58;		# 46
  my $http_urifast58=$59 if $59;
  my $http_urinocase47=$60 if $60;	# 47
  my $distance34=$61 if defined($61);	# 48
  my $distance35=$62 if defined($62);	# 49
  my $http_urifast62=$63 if $63;
  my $http_urinocase50=$64 if $64;	# 50
  my $distance36=$65 if defined($65);	# 51
  my $distance37=$66 if defined($66);	# 52
  my $http_uri38=$67 if $67;		# 53
  my $http_urinocase54=$68 if $68;	# 54
  my $http_urinocase57=$57 if $57;	# 57
  my $http_uri43=$60 if $60;		# 60
  my $http_urinocase61=$61 if $61;	# 61
  my $http_urinocase64=$64 if $64;	# 64
  my $http_uri48=$67 if $67;		# 67
  my $http_urinocase68=$68 if $68;	# 68
  my $http_urinocase71=$71 if $71;	# 71
  my $http_uri53=$74 if $74;		# 74
  my $http_urinocase75=$75 if $75;	# 75
  my $http_urinocase78=$78 if $78;	# 78
  my $http_uri58=$81 if $81;		# 81
  my $http_urinocase82=$82 if $82;	# 82
  my $http_urinocase85=$85 if $85;	# 85
  my $http_uri63=$88 if $88;		# 88
  my $http_urinocase89=$89 if $89;	# 89
  my $http_urinocase92=$92 if $92;	# 92
  my $http_header68=$95 if $95;		# 95
  my $http_headernocase96=$96 if $96;	# 96
  my $http_headernocase99=$99 if $99;	# 99
  my $http_header121=$121 if $121;
  my $http_headerfast122=$122 if $122;
  my $http_headernocase123=$123 if $123;
  my $distance124=$124 if defined($124);
  my $distance125=$125 if defined($125);
  my $http_headerfast126=$126 if $126;
  my $http_headernocase127=$127 if $127;
  my $distance128=$128 if defined($128);
  my $distance129=$129 if defined($129);
  my $pcre_uri73=$130 if $130;		# 102
  my $http_header74=$131 if $131;	# 103
  my $http_headerfast132=$132 if $132;
  my $http_headernocase104=$133 if $133;# 104
  my $distance75=$134 if defined($134);	# 105
  my $distance76=$135 if defined($135);	# 106
  my $http_headerfast136=$136 if $136;
  my $http_headernocase107=$137 if $137;# 107
  my $distance77=$138 if defined($138);	# 108
  my $distance78=$139 if defined($139);	# 109
  my $pcre_agent79=$140 if $140;	# 110

  # check what is http_uri best length ?
  my $httpuricourt=0;
  my $http_uri03_length=0;
  my $http_uri08_length=0;
  my $http_uri13_length=0;
  my $http_uri18_length=0;
  my $http_uri23_length=0;
  my $http_uri28_length=0;
  my $http_uri33_length=0;
  my $http_uri38_length=0;
  my $http_uri43_length=0;
  my $http_uri48_length=0;
  my $http_uri53_length=0;
  my $http_uri58_length=0;
  my $http_uri63_length=0;
  $http_uri03_length=length($http_uri03) if $http_uri03;
  $http_uri08_length=length($http_uri08) if $http_uri08;
  $http_uri13_length=length($http_uri13) if $http_uri13;
  $http_uri18_length=length($http_uri18) if $http_uri18;
  $http_uri23_length=length($http_uri23) if $http_uri23;
  $http_uri28_length=length($http_uri28) if $http_uri28;
  $http_uri33_length=length($http_uri33) if $http_uri33;
  $http_uri38_length=length($http_uri38) if $http_uri38;
  $http_uri43_length=length($http_uri43) if $http_uri43;
  $http_uri48_length=length($http_uri48) if $http_uri48;
  $http_uri53_length=length($http_uri53) if $http_uri53;
  $http_uri58_length=length($http_uri58) if $http_uri58;
  $http_uri63_length=length($http_uri63) if $http_uri63;
  if( $http_uri03_length >= $http_uri08_length && $http_uri03_length >= $http_uri13_length && $http_uri03_length >= $http_uri18_length && $http_uri03_length >= $http_uri23_length && $http_uri03_length >= $http_uri28_length && $http_uri03_length >= $http_uri33_length && $http_uri03_length >= $http_uri38_length && $http_uri03_length >= $http_uri43_length && $http_uri03_length >= $http_uri48_length && $http_uri03_length >= $http_uri53_length && $http_uri03_length >= $http_uri58_length && $http_uri03_length >= $http_uri63_length)
  { $httpuricourt=$http_uri03; }
  elsif( $http_uri08_length >= $http_uri03_length && $http_uri08_length >= $http_uri13_length && $http_uri08_length >= $http_uri18_length && $http_uri08_length >= $http_uri23_length && $http_uri08_length >= $http_uri28_length && $http_uri08_length >= $http_uri33_length && $http_uri08_length >= $http_uri38_length && $http_uri08_length >= $http_uri43_length && $http_uri08_length >= $http_uri48_length && $http_uri08_length >= $http_uri53_length && $http_uri08_length >= $http_uri58_length && $http_uri08_length >= $http_uri63_length)
  { $httpuricourt=$http_uri08; }
  elsif( $http_uri13_length >= $http_uri03_length && $http_uri13_length >= $http_uri08_length && $http_uri13_length >= $http_uri18_length && $http_uri13_length >= $http_uri23_length && $http_uri13_length >= $http_uri28_length && $http_uri13_length >= $http_uri33_length && $http_uri13_length >= $http_uri38_length && $http_uri13_length >= $http_uri43_length && $http_uri13_length >= $http_uri48_length && $http_uri13_length >= $http_uri53_length && $http_uri13_length >= $http_uri58_length && $http_uri13_length >= $http_uri63_length)
  { $httpuricourt=$http_uri13; }
  elsif( $http_uri18_length >= $http_uri03_length && $http_uri18_length >= $http_uri08_length && $http_uri18_length >= $http_uri13_length && $http_uri18_length >= $http_uri23_length && $http_uri18_length >= $http_uri28_length && $http_uri18_length >= $http_uri33_length && $http_uri18_length >= $http_uri38_length && $http_uri18_length >= $http_uri43_length && $http_uri18_length >= $http_uri48_length && $http_uri18_length >= $http_uri53_length && $http_uri18_length >= $http_uri58_length && $http_uri18_length >= $http_uri63_length)
  { $httpuricourt=$http_uri18; }
  elsif( $http_uri23_length >= $http_uri03_length && $http_uri23_length >= $http_uri08_length && $http_uri23_length >= $http_uri13_length && $http_uri23_length >= $http_uri18_length && $http_uri23_length >= $http_uri28_length && $http_uri23_length >= $http_uri33_length && $http_uri23_length >= $http_uri38_length && $http_uri23_length >= $http_uri43_length && $http_uri23_length >= $http_uri48_length && $http_uri23_length >= $http_uri53_length && $http_uri23_length >= $http_uri58_length && $http_uri23_length >= $http_uri63_length)
  { $httpuricourt=$http_uri23; }
  elsif( $http_uri28_length >= $http_uri03_length && $http_uri28_length >= $http_uri08_length && $http_uri28_length >= $http_uri13_length && $http_uri28_length >= $http_uri18_length && $http_uri28_length >= $http_uri23_length && $http_uri28_length >= $http_uri33_length && $http_uri28_length >= $http_uri38_length && $http_uri28_length >= $http_uri43_length && $http_uri28_length >= $http_uri48_length && $http_uri28_length >= $http_uri53_length && $http_uri28_length >= $http_uri58_length && $http_uri28_length >= $http_uri63_length)
  { $httpuricourt=$http_uri28; }
  elsif( $http_uri33_length >= $http_uri03_length && $http_uri33_length >= $http_uri08_length && $http_uri33_length >= $http_uri13_length && $http_uri33_length >= $http_uri18_length && $http_uri33_length >= $http_uri23_length && $http_uri33_length >= $http_uri28_length && $http_uri33_length >= $http_uri38_length && $http_uri33_length >= $http_uri43_length && $http_uri33_length >= $http_uri48_length && $http_uri33_length >= $http_uri53_length && $http_uri33_length >= $http_uri58_length && $http_uri33_length >= $http_uri63_length)
  { $httpuricourt=$http_uri33; }
  elsif( $http_uri38_length >= $http_uri03_length && $http_uri38_length >= $http_uri08_length && $http_uri38_length >= $http_uri13_length && $http_uri38_length >= $http_uri18_length && $http_uri38_length >= $http_uri23_length && $http_uri38_length >= $http_uri28_length && $http_uri38_length >= $http_uri33_length && $http_uri38_length >= $http_uri43_length && $http_uri38_length >= $http_uri48_length && $http_uri38_length >= $http_uri53_length && $http_uri38_length >= $http_uri58_length && $http_uri38_length >= $http_uri63_length)
  { $httpuricourt=$http_uri38; }
  elsif( $http_uri43_length >= $http_uri03_length && $http_uri43_length >= $http_uri08_length && $http_uri43_length >= $http_uri13_length && $http_uri43_length >= $http_uri18_length && $http_uri43_length >= $http_uri23_length && $http_uri43_length >= $http_uri28_length && $http_uri43_length >= $http_uri33_length && $http_uri43_length >= $http_uri38_length && $http_uri43_length >= $http_uri48_length && $http_uri43_length >= $http_uri53_length && $http_uri43_length >= $http_uri58_length && $http_uri43_length >= $http_uri63_length)
  { $httpuricourt=$http_uri43; }
  elsif( $http_uri48_length >= $http_uri03_length && $http_uri48_length >= $http_uri08_length && $http_uri48_length >= $http_uri13_length && $http_uri48_length >= $http_uri18_length && $http_uri48_length >= $http_uri23_length && $http_uri48_length >= $http_uri28_length && $http_uri48_length >= $http_uri33_length && $http_uri48_length >= $http_uri38_length && $http_uri48_length >= $http_uri43_length && $http_uri48_length >= $http_uri53_length && $http_uri48_length >= $http_uri58_length && $http_uri48_length >= $http_uri63_length)
  { $httpuricourt=$http_uri48; }
  elsif( $http_uri53_length >= $http_uri03_length && $http_uri53_length >= $http_uri08_length && $http_uri53_length >= $http_uri13_length && $http_uri53_length >= $http_uri18_length && $http_uri53_length >= $http_uri23_length && $http_uri53_length >= $http_uri28_length && $http_uri53_length >= $http_uri33_length && $http_uri53_length >= $http_uri38_length && $http_uri53_length >= $http_uri43_length && $http_uri53_length >= $http_uri48_length && $http_uri53_length >= $http_uri58_length && $http_uri53_length >= $http_uri63_length)
  { $httpuricourt=$http_uri53; }
  elsif( $http_uri58_length >= $http_uri03_length && $http_uri58_length >= $http_uri08_length && $http_uri58_length >= $http_uri13_length && $http_uri58_length >= $http_uri18_length && $http_uri58_length >= $http_uri23_length && $http_uri58_length >= $http_uri28_length && $http_uri58_length >= $http_uri33_length && $http_uri58_length >= $http_uri38_length && $http_uri58_length >= $http_uri43_length && $http_uri58_length >= $http_uri48_length && $http_uri58_length >= $http_uri53_length && $http_uri58_length >= $http_uri63_length)
  { $httpuricourt=$http_uri58; }
  elsif( $http_uri63_length >= $http_uri03_length && $http_uri63_length >= $http_uri08_length && $http_uri63_length >= $http_uri13_length && $http_uri63_length >= $http_uri18_length && $http_uri63_length >= $http_uri23_length && $http_uri63_length >= $http_uri28_length && $http_uri63_length >= $http_uri33_length && $http_uri63_length >= $http_uri38_length && $http_uri63_length >= $http_uri43_length && $http_uri63_length >= $http_uri48_length && $http_uri63_length >= $http_uri53_length && $http_uri63_length >= $http_uri58_length)
  { $httpuricourt=$http_uri63; }

  $http_uri03 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri03; # (
  $http_uri03 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri03; # )
  $http_uri03 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri03; # *
  $http_uri03 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri03; # +
  $http_uri03 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri03; # -
  $http_uri03 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri03; # .
  $http_uri03 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri03; # /
  $http_uri03 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri03; # ?
  $http_uri03 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri03; # [
  $http_uri03 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri03; # ]
  $http_uri03 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri03; # ^
  $http_uri03 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri03; # {
  $http_uri03 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri03; # }
  $http_uri08 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri08; # (
  $http_uri08 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri08; # )
  $http_uri08 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri08; # *
  $http_uri08 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri08; # +
  $http_uri08 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri08; # -
  $http_uri08 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri08; # .
  $http_uri08 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri08; # /
  $http_uri08 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri08; # ?
  $http_uri08 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri08; # [
  $http_uri08 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri08; # ]
  $http_uri08 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri08; # ^
  $http_uri08 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri08; # {
  $http_uri08 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri08; # }
  $http_uri13 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri13; # (
  $http_uri13 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri13; # )
  $http_uri13 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri13; # *
  $http_uri13 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri13; # +
  $http_uri13 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri13; # -
  $http_uri13 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri13; # .
  $http_uri13 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri13; # /
  $http_uri13 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri13; # ?
  $http_uri13 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri13; # [
  $http_uri13 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri13; # ]
  $http_uri13 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri13; # ^
  $http_uri13 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri13; # {
  $http_uri13 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri13; # }
  $http_uri18 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri18; # (
  $http_uri18 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri18; # )
  $http_uri18 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri18; # *
  $http_uri18 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri18; # +
  $http_uri18 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri18; # -
  $http_uri18 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri18; # .
  $http_uri18 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri18; # /
  $http_uri18 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri18; # ?
  $http_uri18 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri18; # [
  $http_uri18 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri18; # ]
  $http_uri18 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri18; # ^
  $http_uri18 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri18; # {
  $http_uri18 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri18; # }
  $http_uri23 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri23; # (
  $http_uri23 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri23; # )
  $http_uri23 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri23; # *
  $http_uri23 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri23; # +
  $http_uri23 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri23; # -
  $http_uri23 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri23; # .
  $http_uri23 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri23; # /
  $http_uri23 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri23; # ?
  $http_uri23 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri23; # [
  $http_uri23 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri23; # ]
  $http_uri23 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri23; # ^
  $http_uri23 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri23; # {
  $http_uri23 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri23; # }
  $http_uri28 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri28; # (
  $http_uri28 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri28; # )
  $http_uri28 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri28; # *
  $http_uri28 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri28; # +
  $http_uri28 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri28; # -
  $http_uri28 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri28; # .
  $http_uri28 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri28; # /
  $http_uri28 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri28; # ?
  $http_uri28 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri28; # [
  $http_uri28 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri28; # ]
  $http_uri28 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri28; # ^
  $http_uri28 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri28; # {
  $http_uri28 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri28; # }
  $http_uri33 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri33; # (
  $http_uri33 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri33; # )
  $http_uri33 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri33; # *
  $http_uri33 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri33; # +
  $http_uri33 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri33; # -
  $http_uri33 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri33; # .
  $http_uri33 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri33; # /
  $http_uri33 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri33; # ?
  $http_uri33 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri33; # [
  $http_uri33 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri33; # ]
  $http_uri33 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri33; # ^
  $http_uri33 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri33; # {
  $http_uri33 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri33; # }
  $http_uri38 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri38; # (
  $http_uri38 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri38; # )
  $http_uri38 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri38; # *
  $http_uri38 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri38; # +
  $http_uri38 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri38; # -
  $http_uri38 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri38; # .
  $http_uri38 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri38; # /
  $http_uri38 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri38; # ?
  $http_uri38 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri38; # [
  $http_uri38 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri38; # ]
  $http_uri38 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri38; # ^
  $http_uri38 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri38; # {
  $http_uri38 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri38; # }
  $http_uri43 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri43; # (
  $http_uri43 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri43; # )
  $http_uri43 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri43; # *
  $http_uri43 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri43; # +
  $http_uri43 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri43; # -
  $http_uri43 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri43; # .
  $http_uri43 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri43; # /
  $http_uri43 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri43; # ?
  $http_uri43 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri43; # [
  $http_uri43 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri43; # ]
  $http_uri43 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri43; # ^
  $http_uri43 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri43; # {
  $http_uri43 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri43; # }
  $http_uri48 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri48; # (
  $http_uri48 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri48; # )
  $http_uri48 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri48; # *
  $http_uri48 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri48; # +
  $http_uri48 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri48; # -
  $http_uri48 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri48; # .
  $http_uri48 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri48; # /
  $http_uri48 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri48; # ?
  $http_uri48 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri48; # [
  $http_uri48 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri48; # ]
  $http_uri48 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri48; # ^
  $http_uri48 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri48; # {
  $http_uri48 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri48; # }
  $http_uri53 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri53; # (
  $http_uri53 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri53; # )
  $http_uri53 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri53; # *
  $http_uri53 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri53; # +
  $http_uri53 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri53; # -
  $http_uri53 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri53; # .
  $http_uri53 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri53; # /
  $http_uri53 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri53; # ?
  $http_uri53 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri53; # [
  $http_uri53 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri53; # ]
  $http_uri53 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri53; # ^
  $http_uri53 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri53; # {
  $http_uri53 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri53; # }
  $http_uri58 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri58; # (
  $http_uri58 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri58; # )
  $http_uri58 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri58; # *
  $http_uri58 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri58; # +
  $http_uri58 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri58; # -
  $http_uri58 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri58; # .
  $http_uri58 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri58; # /
  $http_uri58 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri58; # ?
  $http_uri58 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri58; # [
  $http_uri58 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri58; # ]
  $http_uri58 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri58; # ^
  $http_uri58 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri58; # {
  $http_uri58 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri58; # }
  $http_uri63 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri63; # (
  $http_uri63 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri63; # )
  $http_uri63 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri63; # *
  $http_uri63 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri63; # +
  $http_uri63 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri63; # -
  $http_uri63 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri63; # .
  $http_uri63 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri63; # /
  $http_uri63 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri63; # ?
  $http_uri63 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri63; # [
  $http_uri63 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri63; # ]
  $http_uri63 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri63; # ^
  $http_uri63 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri63; # {
  $http_uri63 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri63; # }
  $http_header68 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_header68; # (
  $http_header68 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_header68; # )
  $http_header68 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_header68; # *
  $http_header68 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_header68; # +
  $http_header68 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_header68; # -
  $http_header68 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_header68; # .
  $http_header68 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_header68; # /
  $http_header68 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_header68; # ?
  $http_header68 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_header68; # [
  $http_header68 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_header68; # ]
  #$http_header68 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_header68; # ^
  $http_header68 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_header68; # {
  $http_header68 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_header68; # }
  $http_header121 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_header121; # (
  $http_header121 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_header121; # )
  $http_header121 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_header121; # *
  $http_header121 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_header121; # +
  $http_header121 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_header121; # -
  $http_header121 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_header121; # .
  $http_header121 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_header121; # /
  $http_header121 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_header121; # ?
  $http_header121 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_header121; # [
  $http_header121 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_header121; # ]
  #$http_header121 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_header121; # ^
  $http_header121 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_header121; # {
  $http_header121 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_header121; # }
  #$pcre_uri73 =~ s/(?<!\x5C)\x24//g         if $pcre_uri73; # $
  $http_header74 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_header74; # (
  $http_header74 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_header74; # )
  $http_header74 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_header74; # *
  $http_header74 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_header74; # +
  $http_header74 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_header74; # -
  $http_header74 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_header74; # .
  $http_header74 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_header74; # /
  $http_header74 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_header74; # ?
  $http_header74 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_header74; # [
  $http_header74 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_header74; # ]
  $http_header74 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_header74; # {
  $http_header74 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_header74; # }
  #$http_header74 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_header74; # ^
  #$pcre_agent79 =~ s/(?<!\x5C)\x24//g         if $pcre_agent79; # $

#perl -e '$abc1="1|20 21|2|22 24|3";while($abc1=~/(?<!\x5C)\|(.*?)\|/g){$toto1=$1;print "abc1:$abc1\ntoto1:$toto1\n";$toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g; print "$toto1\n"; $abc1=~s/(?<!\x5C)\|.*?\|/$toto1/}; print "final:$abc1\n"'
  while($http_uri03 && $http_uri03=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_uri03=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  while($http_uri08 && $http_uri08=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_uri08=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  while($http_uri13 && $http_uri13=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_uri13=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
   while($http_uri18 && $http_uri18=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_uri18=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  while($http_uri23 && $http_uri23=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_uri23=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  while($http_uri28 && $http_uri28=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_uri28=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  while($http_uri33 && $http_uri33=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_uri33=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  while($http_uri38 && $http_uri38=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_uri38=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  while($http_uri43 && $http_uri43=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_uri43=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  while($http_uri48 && $http_uri48=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_uri48=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  while($http_uri53 && $http_uri53=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_uri53=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  while($http_uri58 && $http_uri58=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_uri58=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  while($http_uri63 && $http_uri63=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_uri63=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  while($http_header68 && $http_header68=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_header68=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  while($http_header121 && $http_header121=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_header121=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  # ne pas faire d'echappement sur la pcre ($pcre_uri73)
  while($http_header74 && $http_header74=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_header74=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  # ne pas faire d'echappement sur la pcre ($pcre_agent79)
  my $abc1=0;
  my $httppcreagent=0;
  my $httpagentshort=0;
  my $pcrereferer=0;
  my @tableauuri1;
  if( $pcre_uri73 && $http_uri03 && $pcre_uri73=~/\Q$http_uri03\E/i ) {
   undef $http_uri03;
   print "ok trouver grep3a\n" if $debug1;
  }
  elsif( $pcre_uri73 && $http_uri03 && $http_uri03=~s/\&/\\x26/g && $pcre_uri73=~/\Q$http_uri03\E/i ) {
   undef $http_uri03;
   print "ok trouver grep3b\n" if $debug1;
  }
  elsif( $pcre_uri73 && $http_uri03 && $http_uri03=~s/\=/\\x3D/g && $pcre_uri73=~/\Q$http_uri03\E/i ) {
   undef $http_uri03;
   print "ok trouver grep3c\n" if $debug1;
  }
  if( $pcre_uri73 && $http_uri08 && $pcre_uri73=~/\Q$http_uri08\E/i ) {
   undef $http_uri08;
   print "ok trouver grep8a\n" if $debug1;
  }
  elsif( $pcre_uri73 && $http_uri08 && $http_uri08=~s/\&/\\x26/g && $pcre_uri73=~/\Q$http_uri08\E/i ) {
   undef $http_uri08;
   print "ok trouver grep8b\n" if $debug1;
  }
  elsif( $pcre_uri73 && $http_uri08 && $http_uri08=~s/\=/\\x3D/g && $pcre_uri73=~/\Q$http_uri08\E/i ) {
   undef $http_uri08;
   print "ok trouver grep8c\n" if $debug1;
  }
  if( $pcre_uri73 && $http_uri13 && $pcre_uri73=~/\Q$http_uri13\E/i ) {
   undef $http_uri13;
   print "ok trouver grep13a\n" if $debug1;
  }
  elsif( $pcre_uri73 && $http_uri13 && $http_uri13=~s/\&/\\x26/g && $pcre_uri73=~/\Q$http_uri13\E/i ) {
   undef $http_uri13;
   print "ok trouver grep13b\n" if $debug1;
  }
  elsif( $pcre_uri73 && $http_uri13 && $http_uri13=~s/\=/\\x3D/g && $pcre_uri73=~/\Q$http_uri13\E/i ) {
   undef $http_uri13;
   print "ok trouver grep13c\n" if $debug1;
  }
  if( $pcre_uri73 && $http_uri18 && $pcre_uri73=~/\Q$http_uri18\E/i ) {
   undef $http_uri18;
   print "ok trouver grep18a\n" if $debug1;
  }
  elsif( $pcre_uri73 && $http_uri18 && $http_uri18=~s/\&/\\x26/g && $pcre_uri73=~/\Q$http_uri18\E/i ) {
   undef $http_uri18;
   print "ok trouver grep18b\n" if $debug1;
  }
  elsif( $pcre_uri73 && $http_uri18 && $http_uri18=~s/\=/\\x3D/g && $pcre_uri73=~/\Q$http_uri18\E/i ) {
   undef $http_uri18;
   print "ok trouver grep18c\n" if $debug1;
  }
  if( $pcre_uri73 && $http_uri23 && $pcre_uri73=~/\Q$http_uri23\E/i ) {
   undef $http_uri23;
   print "ok trouver grep23a\n" if $debug1;
  }
  elsif( $pcre_uri73 && $http_uri23 && $http_uri23=~s/\&/\\x26/g && $pcre_uri73=~/\Q$http_uri23\E/i ) {
   undef $http_uri23;
   print "ok trouver grep23b\n" if $debug1;
  }
  elsif( $pcre_uri73 && $http_uri23 && $http_uri23=~s/\=/\\x3D/g && $pcre_uri73=~/\Q$http_uri23\E/i ) {
   undef $http_uri23;
   print "ok trouver grep23c\n" if $debug1;
  }
  if( $pcre_uri73 && $http_uri28 && $pcre_uri73=~/\Q$http_uri28\E/i ) {
   undef $http_uri28;
   print "ok trouver grep28a\n" if $debug1;
  }
  elsif( $pcre_uri73 && $http_uri28 && $http_uri28=~s/\&/\\x26/g && $pcre_uri73=~/\Q$http_uri28\E/i ) {
   undef $http_uri28;
   print "ok trouver grep28b\n" if $debug1;
  }
  elsif( $pcre_uri73 && $http_uri28 && $http_uri28=~s/\=/\\x3D/g && $pcre_uri73=~/\Q$http_uri28\E/i ) {
   undef $http_uri28;
   print "ok trouver grep28c\n" if $debug1;
  }
  if( $pcre_uri73 && $http_uri33 && $pcre_uri73=~/\Q$http_uri33\E/i ) {
   undef $http_uri33;
   print "ok trouver grep33a\n" if $debug1;
  }
  elsif( $pcre_uri73 && $http_uri33 && $http_uri33=~s/\&/\\x26/g && $pcre_uri73=~/\Q$http_uri33\E/i ) {
   undef $http_uri33;
   print "ok trouver grep33b\n" if $debug1;
  }
  elsif( $pcre_uri73 && $http_uri33 && $http_uri33=~s/\=/\\x3D/g && $pcre_uri73=~/\Q$http_uri33\E/i ) {
   undef $http_uri33;
   print "ok trouver grep33c\n" if $debug1;
  }
  if( $pcre_uri73 && $http_uri38 && $pcre_uri73=~/\Q$http_uri38\E/i ) {
   undef $http_uri38;
   print "ok trouver grep38a\n" if $debug1;
  }
  elsif( $pcre_uri73 && $http_uri38 && $http_uri38=~s/\&/\\x26/g && $pcre_uri73=~/\Q$http_uri38\E/i ) {
   undef $http_uri38;
   print "ok trouver grep38b\n" if $debug1;
  }
  elsif( $pcre_uri73 && $http_uri38 && $http_uri38=~s/\=/\\x3D/g && $pcre_uri73=~/\Q$http_uri38\E/i ) {
   undef $http_uri38;
   print "ok trouver grep38c\n" if $debug1;
  }
  if( $pcre_uri73 && $http_uri43 && $pcre_uri73=~/\Q$http_uri43\E/i ) {
   undef $http_uri43;
   print "ok trouver grep43a\n" if $debug1;
  }
  elsif( $pcre_uri73 && $http_uri43 && $http_uri43=~s/\&/\\x26/g && $pcre_uri73=~/\Q$http_uri43\E/i ) {
   undef $http_uri43;
   print "ok trouver grep43b\n" if $debug1;
  }
  elsif( $pcre_uri73 && $http_uri43 && $http_uri43=~s/\=/\\x3D/g && $pcre_uri73=~/\Q$http_uri43\E/i ) {
   undef $http_uri43;
   print "ok trouver grep43c\n" if $debug1;
  }
  if( $pcre_uri73 && $http_uri48 && $pcre_uri73=~/\Q$http_uri48\E/i ) {
   undef $http_uri48;
   print "ok trouver grep48a\n" if $debug1;
  }
  elsif( $pcre_uri73 && $http_uri48 && $http_uri48=~s/\&/\\x26/g && $pcre_uri73=~/\Q$http_uri48\E/i ) {
   undef $http_uri48;
   print "ok trouver grep48b\n" if $debug1;
  }
  elsif( $pcre_uri73 && $http_uri48 && $http_uri48=~s/\=/\\x3D/g && $pcre_uri73=~/\Q$http_uri48\E/i ) {
   undef $http_uri48;
   print "ok trouver grep48c\n" if $debug1;
  }
  if( $pcre_uri73 && $http_uri53 && $pcre_uri73=~/\Q$http_uri53\E/i ) {
   undef $http_uri53;
   print "ok trouver grep53a\n" if $debug1;
  }
  elsif( $pcre_uri73 && $http_uri53 && $http_uri53=~s/\&/\\x26/g && $pcre_uri73=~/\Q$http_uri53\E/i ) {
   undef $http_uri53;
   print "ok trouver grep53b\n" if $debug1;
  }
  elsif( $pcre_uri73 && $http_uri53 && $http_uri53=~s/\=/\\x3D/g && $pcre_uri73=~/\Q$http_uri53\E/i ) {
   undef $http_uri53;
   print "ok trouver grep53c\n" if $debug1;
  }
  if( $pcre_uri73 && $http_uri58 && $pcre_uri73=~/\Q$http_uri58\E/i ) {
   undef $http_uri58;
   print "ok trouver grep58a\n" if $debug1;
  }
  elsif( $pcre_uri73 && $http_uri58 && $http_uri58=~s/\&/\\x26/g && $pcre_uri73=~/\Q$http_uri58\E/i ) {
   undef $http_uri58;
   print "ok trouver grep58b\n" if $debug1;
  }
  elsif( $pcre_uri73 && $http_uri58 && $http_uri58=~s/\=/\\x3D/g && $pcre_uri73=~/\Q$http_uri58\E/i ) {
   undef $http_uri58;
   print "ok trouver grep58c\n" if $debug1;
  }
  if( $pcre_uri73 && $http_uri63 && $pcre_uri73=~/\Q$http_uri63\E/i ) {
   undef $http_uri63;
   print "ok trouver grep63a\n" if $debug1;
  }
  elsif( $pcre_uri73 && $http_uri63 && $http_uri63=~s/\&/\\x26/g && $pcre_uri73=~/\Q$http_uri63\E/i ) {
   undef $http_uri63;
   print "ok trouver grep63b\n" if $debug1;
  }
  elsif( $pcre_uri73 && $http_uri63 && $http_uri63=~s/\=/\\x3D/g && $pcre_uri73=~/\Q$http_uri63\E/i ) {
   undef $http_uri63;
   print "ok trouver grep63c\n" if $debug1;
  }

     if( $http_header68 && $http_header68 =~ s/\QUser\-Agent\x3A\x20\E(?!$)/^/i ) { }
  elsif( $http_header68 && $http_header68 =~ s/\QUser\-Agent\x3A\x20\E$/^/i ) { undef($http_header68) }
  elsif( $http_header68 && $http_header68 =~ s/\QUser\-Agent\x3A \E(?!$)/^/i ) { }
  elsif( $http_header68 && $http_header68 =~  /\QUser\-Agent\x3A \E$/i ) { undef($http_header68) }
  elsif( $http_header68 && $http_header68 =~ s/\QUser-Agent\x3A \E(?!$)/^/i ) { }
  elsif( $http_header68 && $http_header68 =~  /\QUser-Agent\x3A \E$/i ) { undef($http_header68) }
  elsif( $http_header68 && $http_header68 =~ s/\QUser\-Agent\: \E(?!$)/^/i ) { }
  elsif( $http_header68 && $http_header68 =~  /\QUser\-Agent\: \E$/i ) { undef($http_header68) }
  elsif( $http_header68 && $http_header68 =~ s/\QUser-Agent\: \E(?!$)/^/i ) { }
  elsif( $http_header68 && $http_header68 =~  /\QUser-Agent\: \E$/i ) { undef($http_header68) }
  elsif( $http_header68 && $http_header68 =~ s/\QUser\-Agent\x3A\E(?!$)/^/i ) { }
  elsif( $http_header68 && $http_header68 =~  /\QUser\-Agent\x3A\E$/i ) { undef($http_header68) }
  elsif( $http_header68 && $http_header68 =~ s/\QUser-Agent\x3A\E(?!$)/^/i ) { }
  elsif( $http_header68 && $http_header68 =~  /\QUser-Agent\x3A\E$/i ) { undef($http_header68) }
  elsif( $http_header68 && $http_header68 =~ s/\QUser\-Agent\:\E(?!$)/^/i ) { }
  elsif( $http_header68 && $http_header68 =~  /\QUser\-Agent\:\E$/i ) { undef($http_header68) }
  elsif( $http_header68 && $http_header68 =~ s/\QUser-Agent\:\E(?!$)/^/i ) { }
  elsif( $http_header68 && $http_header68 =~  /\QUser-Agent\:\E$/i ) { undef($http_header68) }
                           $http_header68 =~ s/\Q\x0D\x0A\E/\$/i if $http_header68;
     if( $http_header121 && $http_header121 =~ s/\QUser\-Agent\x3A\x20\E(?!$)/^/i ) { }
  elsif( $http_header121 && $http_header121 =~ s/\QUser\-Agent\x3A\x20\E$/^/i ) { undef($http_header121) }
  elsif( $http_header121 && $http_header121 =~ s/\QUser\-Agent\x3A \E(?!$)/^/i ) { }
  elsif( $http_header121 && $http_header121 =~  /\QUser\-Agent\x3A \E$/i ) { undef($http_header121) }
  elsif( $http_header121 && $http_header121 =~ s/\QUser-Agent\x3A \E(?!$)/^/i ) { }
  elsif( $http_header121 && $http_header121 =~  /\QUser-Agent\x3A \E$/i ) { undef($http_header121) }
  elsif( $http_header121 && $http_header121 =~ s/\QUser\-Agent\: \E(?!$)/^/i ) { }
  elsif( $http_header121 && $http_header121 =~  /\QUser\-Agent\: \E$/i ) { undef($http_header121) }
  elsif( $http_header121 && $http_header121 =~ s/\QUser-Agent\: \E(?!$)/^/i ) { }
  elsif( $http_header121 && $http_header121 =~  /\QUser-Agent\: \E$/i ) { undef($http_header121) }
  elsif( $http_header121 && $http_header121 =~ s/\QUser\-Agent\x3A\E(?!$)/^/i ) { }
  elsif( $http_header121 && $http_header121 =~  /\QUser\-Agent\x3A\E$/i ) { undef($http_header121) }
  elsif( $http_header121 && $http_header121 =~ s/\QUser-Agent\x3A\E(?!$)/^/i ) { }
  elsif( $http_header121 && $http_header121 =~  /\QUser-Agent\x3A\E$/i ) { undef($http_header121) }
  elsif( $http_header121 && $http_header121 =~ s/\QUser\-Agent\:\E(?!$)/^/i ) { }
  elsif( $http_header121 && $http_header121 =~  /\QUser\-Agent\:\E$/i ) { undef($http_header121) }
  elsif( $http_header121 && $http_header121 =~ s/\QUser-Agent\:\E(?!$)/^/i ) { }
  elsif( $http_header121 && $http_header121 =~  /\QUser-Agent\:\E$/i ) { undef($http_header121) }
                           $http_header121 =~ s/\Q\x0D\x0A\E/\$/i if $http_header121;
     if( $http_header74 && $http_header74 =~ s/\QUser\-Agent\x3A\x20\E(?!$)/^/i ) { }
  elsif( $http_header74 && $http_header74 =~ s/\QUser\-Agent\x3A\x20\E$/^/i ) { undef($http_header74) }
  elsif( $http_header74 && $http_header74 =~ s/\QUser\-Agent\x3A \E(?!$)/^/i ) { }
  elsif( $http_header74 && $http_header74 =~  /\QUser\-Agent\x3A \E$/i ) { undef($http_header74) }
  elsif( $http_header74 && $http_header74 =~ s/\QUser-Agent\x3A \E(?!$)/^/i ) { }
  elsif( $http_header74 && $http_header74 =~  /\QUser-Agent\x3A \E$/i ) { undef($http_header74) }
  elsif( $http_header74 && $http_header74 =~ s/\QUser\-Agent\: \E(?!$)/^/i ) { }
  elsif( $http_header74 && $http_header74 =~  /\QUser\-Agent\: \E$/i ) { undef($http_header74) }
  elsif( $http_header74 && $http_header74 =~ s/\QUser-Agent\: \E(?!$)/^/i ) { }
  elsif( $http_header74 && $http_header74 =~  /\QUser-Agent\: \E$/i ) { undef($http_header74) }
  elsif( $http_header74 && $http_header74 =~ s/\QUser\-Agent\x3A\E(?!$)/^/i ) { }
  elsif( $http_header74 && $http_header74 =~  /\QUser\-Agent\x3A\E$/i ) { undef($http_header74) }
  elsif( $http_header74 && $http_header74 =~ s/\QUser-Agent\x3A\E(?!$)/^/i ) { }
  elsif( $http_header74 && $http_header74 =~  /\QUser-Agent\x3A\E$/i ) { undef($http_header74) }
  elsif( $http_header74 && $http_header74 =~ s/\QUser\-Agent\:\E(?!$)/^/i ) { }
  elsif( $http_header74 && $http_header74 =~  /\QUser\-Agent\:\E$/i ) { undef($http_header74) }
  elsif( $http_header74 && $http_header74 =~ s/\QUser-Agent\:\E(?!$)/^/i ) { }
  elsif( $http_header74 && $http_header74 =~  /\QUser-Agent\:\E$/i ) { undef($http_header74) }
                           $http_header74 =~ s/\Q\x0D\x0A\E/\$/i if $http_header74;
  $pcre_agent79 =~ s/\Q^User\-Agent\x3A\x20\E/^/i if $pcre_agent79;
  $pcre_agent79 =~ s/\Q^User\-Agent\x3A \E/^/i if $pcre_agent79;
  $pcre_agent79 =~ s/\QUser\-Agent\x3A\x20\E/^/i if $pcre_agent79;
  $pcre_agent79 =~ s/\QUser\-Agent\x3A \E/^/i if $pcre_agent79;
  $pcre_agent79 =~ s/\Q^User-Agent\x3A\x20\E/^/i if $pcre_agent79;
  $pcre_agent79 =~ s/\Q^User-Agent\x3A \E/^/i if $pcre_agent79;
  $pcre_agent79 =~ s/\QUser-Agent\x3A\x20\E/^/i if $pcre_agent79;
  $pcre_agent79 =~ s/\QUser-Agent\x3A \E/^/i if $pcre_agent79;
  $pcre_agent79 =~ s/\Q^User\-Agent\:\x20\E/^/i if $pcre_agent79;
  $pcre_agent79 =~ s/\Q^User\-Agent\: \E/^/i if $pcre_agent79;
  $pcre_agent79 =~ s/\QUser\-Agent\:\x20\E/^/i if $pcre_agent79;
  $pcre_agent79 =~ s/\QUser\-Agent\: \E/^/i if $pcre_agent79;
  $pcre_agent79 =~ s/\Q^User-Agent\:\x20\E/^/i if $pcre_agent79;
  $pcre_agent79 =~ s/\Q^User-Agent\: \E/^/i if $pcre_agent79;
  $pcre_agent79 =~ s/\QUser-Agent\:\x20\E/^/i if $pcre_agent79;
  $pcre_agent79 =~ s/\QUser-Agent\: \E/^/i if $pcre_agent79;
  $pcre_agent79 =~ s/\Q^User\-Agent\x3A\E/^/i if $pcre_agent79;
  $pcre_agent79 =~ s/\QUser\-Agent\x3A\E/^/i if $pcre_agent79;
  $pcre_agent79 =~ s/\Q^User-Agent\x3A\E/^/i if $pcre_agent79;
  $pcre_agent79 =~ s/\QUser-Agent\x3A\E/^/i if $pcre_agent79;
  $pcre_agent79 =~ s/\Q^User\-Agent\:\E/^/i if $pcre_agent79;
  $pcre_agent79 =~ s/\QUser\-Agent\:\E/^/i if $pcre_agent79;
  $pcre_agent79 =~ s/\Q^User-Agent\:\E/^/i if $pcre_agent79;
  $pcre_agent79 =~ s/\QUser-Agent\:\E/^/i if $pcre_agent79;
  $pcre_agent79 =~ s/\Q\x0D\x0A\E/\$/i if $pcre_agent79;
  $pcre_agent79 =~ s/\\r\?\$/\$/i if $pcre_agent79;
  $pcre_agent79 =~ s/\\r\$/\$/i if $pcre_agent79;
     if( $http_header68  && $http_header68 =~ s/\Q^Referer\x3A\x20\E/^/i ) { $pcrereferer = $http_header68; undef $http_header68 }
  elsif( $http_header68  && $http_header68 =~ s/\Q^Referer\x3A \E/^/i ) { $pcrereferer = $http_header68; undef $http_header68 }
  elsif( $http_header68  && $http_header68 =~ s/\QReferer\x3A\x20\E/^/i ) { $pcrereferer = $http_header68; undef $http_header68 }
  elsif( $http_header68  && $http_header68 =~ s/\QReferer\x3A \E/^/i ) { $pcrereferer = $http_header68; undef $http_header68 }
  elsif( $http_header68  && $http_header68 =~ s/\Q^Referer\x3A\E/^/i ) { $pcrereferer = $http_header68; undef $http_header68 }
  elsif( $http_header68  && $http_header68 =~ s/\QReferer\x3A\E/^/i ) { $pcrereferer = $http_header68; undef $http_header68 }
     if( $http_header121 && $http_header121 =~ s/\Q^Referer\x3A\x20\E/^/i ) { $pcrereferer = $http_header121; undef $http_header121 }
  elsif( $http_header121 && $http_header121 =~ s/\Q^Referer\x3A \E/^/i ) { $pcrereferer = $http_header121; undef $http_header121 }
  elsif( $http_header121 && $http_header121 =~ s/\QReferer\x3A\x20\E/^/i ) { $pcrereferer = $http_header121; undef $http_header121 }
  elsif( $http_header121 && $http_header121 =~ s/\QReferer\x3A \E/^/i ) { $pcrereferer = $http_header121; undef $http_header121 }
  elsif( $http_header121 && $http_header121 =~ s/\Q^Referer\x3A\E/^/i ) { $pcrereferer = $http_header121; undef $http_header121 }
  elsif( $http_header121 && $http_header121 =~ s/\QReferer\x3A\E/^/i ) { $pcrereferer = $http_header121; undef $http_header121 }
     if( $http_header74  && $http_header74 =~ s/\Q^Referer\x3A\x20\E/^/i ) { $pcrereferer = $http_header74; undef $http_header74 }
  elsif( $http_header74  && $http_header74 =~ s/\Q^Referer\x3A \E/^/i ) { $pcrereferer = $http_header74; undef $http_header74 }
  elsif( $http_header74  && $http_header74 =~ s/\QReferer\x3A\x20\E/^/i ) { $pcrereferer = $http_header74; undef $http_header74 }
  elsif( $http_header74  && $http_header74 =~ s/\QReferer\x3A \E/^/i ) { $pcrereferer = $http_header74; undef $http_header74 }
  elsif( $http_header74  && $http_header74 =~ s/\Q^Referer\x3A\E/^/i ) { $pcrereferer = $http_header74; undef $http_header74 }
  elsif( $http_header74  && $http_header74 =~ s/\QReferer\x3A\E/^/i ) { $pcrereferer = $http_header74; undef $http_header74 }
     if( $pcre_agent79   && $pcre_agent79  =~ s/\Q^Referer\x3A\x20\E/^/i ) { $pcrereferer = $pcre_agent79; undef $pcre_agent79 }
  elsif( $pcre_agent79   && $pcre_agent79  =~ s/\Q^Referer\x3A \E/^/i ) { $pcrereferer = $pcre_agent79; undef $pcre_agent79 }
  elsif( $pcre_agent79   && $pcre_agent79  =~ s/\QReferer\x3A\x20\E/^/i ) { $pcrereferer = $pcre_agent79; undef $pcre_agent79 }
  elsif( $pcre_agent79   && $pcre_agent79  =~ s/\QReferer\x3A \E/^/i ) { $pcrereferer = $pcre_agent79; undef $pcre_agent79 }
  elsif( $pcre_agent79   && $pcre_agent79  =~ s/\Q^Referer\x3A\E/^/i ) { $pcrereferer = $pcre_agent79; undef $pcre_agent79 }
  elsif( $pcre_agent79   && $pcre_agent79  =~ s/\QReferer\x3A\E/^/i ) { $pcrereferer = $pcre_agent79; undef $pcre_agent79 }

  if( $pcrereferer )
  {
   $pcrereferer =~ s/\Q^[^\r\n]+?\E//i;
   $pcrereferer =~ s/\Q^[^\r\n]+\E//i;
   $pcrereferer =~ s/\Q^[^\r\n]*?\E//i;
   $pcrereferer =~ s/\Q^[^\r\n]*\E//i;
   $pcrereferer =~ s/\Q^[^\n]+?\E//i;
   $pcrereferer =~ s/\Q^[^\n]+\E//i;
   $pcrereferer =~ s/\Q^[^\n]*?\E//i;
   $pcrereferer =~ s/\Q^[^\n]*\E//i;
  }

  if( $pcre_agent79 )
  {
   $pcre_agent79 =~ s/\Q^[^\r\n]+?\E//i;
   $pcre_agent79 =~ s/\Q^[^\r\n]+\E//i;
   $pcre_agent79 =~ s/\Q^[^\r\n]*?\E//i;
   $pcre_agent79 =~ s/\Q^[^\r\n]*\E//i;
   $pcre_agent79 =~ s/\Q^[^\n]+?\E//i;
   $pcre_agent79 =~ s/\Q^[^\n]+\E//i;
   $pcre_agent79 =~ s/\Q^[^\n]*?\E//i;
   $pcre_agent79 =~ s/\Q^[^\n]*\E//i;
  }

  if( $pcre_uri73 )
  {
   $pcre_uri73 =~ s/^\^\\\//\^(?:https?\\\:\\\/\\\/)?[^\\\/]*?\\\//i;
   $pcre_uri73 =~ s/^\^\\x2F/\^(?:https?\\\:\\\/\\\/)?[^\\\/]*?\\x2F/i;
  }

  # http_user_agent short
  if( $http_header68 && $http_header74 && $http_header121 && length($http_header68) >= (length($http_header74) or length($http_header121)) )
  {
   $httpagentshort= "$http_header68" if $http_header68;
  }
  elsif( $http_header68 && $http_header74 && $http_header121 && length($http_header74) >= (length($http_header68) or length($http_header121)) )
  {
   $httpagentshort= "$http_header74" if $http_header74;
  }
  elsif( $http_header68 && $http_header74 && $http_header121 && length($http_header121) >= (length($http_header68) or length($http_header74)) )
  {
   $httpagentshort= "$http_header121" if $http_header121;
  }
  elsif( $http_header68 && $http_header74 && !$http_header121 && length($http_header68) >= length($http_header74) )
  {
   $httpagentshort= "$http_header68" if $http_header68;
  }
  elsif( $http_header68 && $http_header74 && !$http_header121 && length($http_header74) >= length($http_header68) )
  {
   $httpagentshort= "$http_header74" if $http_header74;
  }
  elsif( $http_header68 && $http_header121 && !$http_header74 && length($http_header68) >= length($http_header121) )
  {
   $httpagentshort= "$http_header68" if $http_header68;
  }
  elsif( $http_header68 && $http_header121 && !$http_header74 && length($http_header121) >= length($http_header68) )
  {
   $httpagentshort= "$http_header121" if $http_header121;
  }
  elsif( $http_header74 && $http_header121 && !$http_header68 && length($http_header74) >= length($http_header121) )
  {
   $httpagentshort= "$http_header74" if $http_header74;
  }
  elsif( $http_header74 && $http_header121 && !$http_header68 && length($http_header121) >= length($http_header74) )
  {
   $httpagentshort= "$http_header121" if $http_header121;
  }
  elsif( $http_header68 && !$http_header74 && !$http_header121 )
  {
   $httpagentshort= "$http_header68" if $http_header68;
  }
  elsif( $http_header74 && !$http_header68 && !$http_header121 )
  {
   $httpagentshort= "$http_header74" if $http_header74;
  }
  elsif( $http_header121 && !$http_header68 && !$http_header74 )
  {
   $httpagentshort= "$http_header121" if $http_header121;
  }

  while( $httpagentshort =~ /\\x(..)/g )
  {
   my $tempochr=chr(hex("$1"));
   $httpagentshort =~ s/\\x(..)/$tempochr/;
  }
  $httpagentshort =~ s/(?:\\|\^|\$)//g;

  if( $pcre_agent79 && $http_header68 && $pcre_agent79=~/\Q$http_header68\E/i ) {
   undef $http_header68;
   print "ok trouver grep68a\n" if $debug1;
  }
  elsif( $pcre_agent79 && $http_header68 && $http_header68=~s/\&/\\x26/g && $pcre_agent79=~/\Q$http_header68\E/i ) {
   undef $http_header68;
   print "ok trouver grep68b\n" if $debug1;
  }
  elsif( $pcre_agent79 && $http_header68 && $http_header68=~s/\=/\\x3D/g && $pcre_agent79=~/\Q$http_header68\E/i ) {
   undef $http_header68;
   print "ok trouver grep68c\n" if $debug1;
  }
  if( $pcre_agent79 && $http_header121 && $pcre_agent79=~/\Q$http_header121\E/i ) {
   undef $http_header121;
   print "ok trouver grep121a\n" if $debug1;
  }
  elsif( $pcre_agent79 && $http_header121 && $http_header121=~s/\&/\\x26/g && $pcre_agent79=~/\Q$http_header121\E/i ) {
   undef $http_header121;
   print "ok trouver grep121b\n" if $debug1;
  }
  elsif( $pcre_agent79 && $http_header121 && $http_header121=~s/\=/\\x3D/g && $pcre_agent79=~/\Q$http_header121\E/i ) {
   undef $http_header121;
   print "ok trouver grep121c\n" if $debug1;
  }
  if( $pcre_agent79 && $http_header74 && $pcre_agent79=~/\Q$http_header74\E/i ) {
   undef $http_header74;
   print "ok trouver grep74a\n" if $debug1;
  }
  elsif( $pcre_agent79 && $http_header74 && $http_header74=~s/\&/\\x26/g && $pcre_agent79=~/\Q$http_header74\E/i ) {
   undef $http_header74;
   print "ok trouver grep74b\n" if $debug1;
  }
  elsif( $pcre_agent79 && $http_header74 && $http_header74=~s/\=/\\x3D/g && $pcre_agent79=~/\Q$http_header74\E/i ) {
   undef $http_header74;
   print "ok trouver grep74c\n" if $debug1;
  }

  # one uri
  #$abc1= "$http_uri03" if $http_uri03 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
  #$abc1= "$http_uri08" if $http_uri08 && !$http_uri03 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
  #$abc1= "$http_uri13" if $http_uri13 && !$http_uri03 && !$http_uri08 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
  #$abc1= "$http_uri18" if $http_uri18 && !$http_uri03 && !$http_uri08 && !$http_uri13 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
  #$abc1= "$http_uri23" if $http_uri23 && !$http_uri03 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
  #$abc1= "$http_uri28" if $http_uri28 && !$http_uri03 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
  #$abc1= "$http_uri33" if $http_uri33 && !$http_uri03 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
  #$abc1= "$http_uri38" if $http_uri38 && !$http_uri03 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
  #$abc1= "$http_uri43" if $http_uri43 && !$http_uri03 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
  #$abc1= "$http_uri48" if $http_uri48 && !$http_uri03 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
  #$abc1= "$http_uri53" if $http_uri53 && !$http_uri03 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
  #$abc1= "$http_uri58" if $http_uri58 && !$http_uri03 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri63 && !$pcre_uri73;
  #$abc1= "$http_uri63" if $http_uri63 && !$http_uri03 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$pcre_uri73;
  $abc1= "$pcre_uri73" if $pcre_uri73 && !$http_uri03 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63;

  # one header
  $httppcreagent= "$http_header68" if $http_header68 && !$http_header121 && !$http_header74 && !$pcre_agent79 && $http_header68 =~ /(?:\\|\^|\$)/;
  $httppcreagent= "$http_header121" if $http_header121 && !$http_header68 && !$http_header74 && !$pcre_agent79 && $http_header121 =~ /(?:\\|\^|\$)/;
  $httppcreagent= "$http_header74" if $http_header74 && !$http_header121 && !$http_header68 && !$pcre_agent79 && $http_header74 =~ /(?:\\|\^|\$)/;
  $httppcreagent= "$pcre_agent79" if $pcre_agent79 && !$http_header68 && !$http_header121 && !$http_header74;

  # two headers
  if( ($http_header68 && $http_header74 && !$http_header121) && (defined($distance75)||defined($distance76)||defined($distance77)||defined($distance78)) ) {
   $httppcreagent= "(?:$http_header68.*?$http_header74)" if $http_header68 && $http_header74;
  }
  elsif( ($http_header68 && $http_header74 && !$http_header121) && !(defined($distance75)||defined($distance76)||defined($distance77)||defined($distance78)) ) {
   $httppcreagent= "(?:$http_header68.*?$http_header74|$http_header74.*?$http_header68)" if $http_header68 && $http_header74;
  }
  elsif( ($http_header68 && !$http_header74 && $http_header121) && (defined($distance124)||defined($distance125)||defined($distance128)||defined($distance129)) ) {
   $httppcreagent= "(?:$http_header68.*?$http_header121)" if $http_header68 && $http_header121;
  }
  elsif( ($http_header68 && !$http_header74 && $http_header121) && !(defined($distance124)||defined($distance125)||defined($distance128)||defined($distance129)) ) {
   $httppcreagent= "(?:$http_header68.*?$http_header121|$http_header121.*?$http_header68)" if $http_header68 && $http_header121;
  }

  # two uri
  if( (defined($distance9)||defined($distance10)||defined($distance11)||defined($distance12)) && !(defined($distance14)||defined($distance15)||defined($distance16)||defined($distance17)) ) {
   $abc1= "(?:$http_uri03.*?$http_uri08)" if $http_uri03 && $http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
  }
  elsif( !(defined($distance9)||defined($distance10)||defined($distance11)||defined($distance12)) && !(defined($distance14)||defined($distance15)||defined($distance16)||defined($distance17)) ) {
   if( $http_uri03 && $http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73 && (( $http_uri03 !~ /\\x|^\^|\$$/ ) or ( $http_uri08 !~ /\\x|^\^|\$$/ )) )
   {
    @tableauuri1 = ( $http_uri03, $http_uri08 ) if $http_uri03 && $http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
    my $tableauuri1index=0;
    foreach( @tableauuri1 )
    {
     $tableauuri1[$tableauuri1index++] =~ s/\\(?!x)//g;
     if( $_ =~ /\\x|^\^|\$$/ ) { undef @tableauuri1 }
    }
   }
   else
   {
   $abc1= "(?:$http_uri03.*?$http_uri08|$http_uri08.*?$http_uri03)" if $http_uri03 && $http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*?$http_uri13|$http_uri13.*?$http_uri03)" if $http_uri03 && $http_uri13 && !$http_uri08 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*?$http_uri18|$http_uri18.*?$http_uri03)" if $http_uri03 && $http_uri18 && !$http_uri08 && !$http_uri13 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*?$http_uri23|$http_uri23.*?$http_uri03)" if $http_uri03 && $http_uri23 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*?$http_uri28|$http_uri28.*?$http_uri03)" if $http_uri03 && $http_uri28 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*?$http_uri33|$http_uri33.*?$http_uri03)" if $http_uri03 && $http_uri33 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*?$http_uri38|$http_uri38.*?$http_uri03)" if $http_uri03 && $http_uri38 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*?$http_uri43|$http_uri43.*?$http_uri03)" if $http_uri03 && $http_uri43 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*?$http_uri48|$http_uri48.*?$http_uri03)" if $http_uri03 && $http_uri48 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*?$http_uri53|$http_uri53.*?$http_uri03)" if $http_uri03 && $http_uri53 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*?$http_uri58|$http_uri58.*?$http_uri03)" if $http_uri03 && $http_uri58 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*?$http_uri63|$http_uri63.*?$http_uri03)" if $http_uri03 && $http_uri63 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*?$pcre_uri73|$pcre_uri73.*?$http_uri03)" if $http_uri03 && $pcre_uri73 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63;
   $abc1= "(?:$http_uri08.*?$pcre_uri73|$pcre_uri73.*?$http_uri08)" if $http_uri08 && $pcre_uri73 && !$http_uri03 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63;
   $abc1= "(?:$http_uri13.*?$pcre_uri73|$pcre_uri73.*?$http_uri13)" if $http_uri13 && $pcre_uri73 && !$http_uri03 && !$http_uri08 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63;
   $abc1= "(?:$http_uri18.*?$pcre_uri73|$pcre_uri73.*?$http_uri18)" if $http_uri18 && $pcre_uri73 && !$http_uri03 && !$http_uri08 && !$http_uri13 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63;
   $abc1= "(?:$http_uri23.*?$pcre_uri73|$pcre_uri73.*?$http_uri23)" if $http_uri23 && $pcre_uri73 && !$http_uri03 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63;
   $abc1= "(?:$http_uri28.*?$pcre_uri73|$pcre_uri73.*?$http_uri28)" if $http_uri28 && $pcre_uri73 && !$http_uri03 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63;
   $abc1= "(?:$http_uri33.*?$pcre_uri73|$pcre_uri73.*?$http_uri33)" if $http_uri33 && $pcre_uri73 && !$http_uri03 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63;
   $abc1= "(?:$http_uri38.*?$pcre_uri73|$pcre_uri73.*?$http_uri38)" if $http_uri38 && $pcre_uri73 && !$http_uri03 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63;
   $abc1= "(?:$http_uri43.*?$pcre_uri73|$pcre_uri73.*?$http_uri43)" if $http_uri43 && $pcre_uri73 && !$http_uri03 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63;
   $abc1= "(?:$http_uri48.*?$pcre_uri73|$pcre_uri73.*?$http_uri48)" if $http_uri48 && $pcre_uri73 && !$http_uri03 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri53 && !$http_uri58 && !$http_uri63;
   $abc1= "(?:$http_uri53.*?$pcre_uri73|$pcre_uri73.*?$http_uri53)" if $http_uri53 && $pcre_uri73 && !$http_uri03 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri58 && !$http_uri63;
   $abc1= "(?:$http_uri58.*?$pcre_uri73|$pcre_uri73.*?$http_uri58)" if $http_uri58 && $pcre_uri73 && !$http_uri03 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri63;
   $abc1= "(?:$http_uri63.*?$pcre_uri73|$pcre_uri73.*?$http_uri63)" if $http_uri63 && $pcre_uri73 && !$http_uri03 && !$http_uri08 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58;
   }
  }

  # three headers
  if( (defined($distance75)||defined($distance76)||defined($distance77)||defined($distance78)) && (defined($distance124)||defined($distance125)||defined($distance128)||defined($distance129)) ) {
    $httppcreagent= "(?:$http_header68.*$http_header121.*$http_header74)" if $http_header68 && $http_header74 && $http_header121 && !$pcre_agent79;
  }
  elsif( !(defined($distance75)||defined($distance76)||defined($distance77)||defined($distance78)) && !(defined($distance124)||defined($distance125)||defined($distance128)||defined($distance129)) ) {
    $httppcreagent= "(?:$http_header68.*$http_header121.*$http_header74|$http_header68.*$http_header74.*$http_header121|$http_header74.*$http_header68.*$http_header121|$http_header74.*$http_header121.*$http_header68)" if $http_header68 && $http_header121 && $http_header74 && !$pcre_agent79;
    $httppcreagent= "(?:$http_header68.*$http_header121.*$pcre_agent79|$http_header68.*$pcre_agent79.*$http_header121|$pcre_agent79.*$http_header68.*$http_header121|$pcre_agent79.*$http_header121.*$http_header68)" if $http_header68 && $http_header121 && $pcre_agent79 && !$http_header74;
  }
 
  # three uri
  if( (defined($distance9)||defined($distance10)||defined($distance11)||defined($distance12)) && (defined($distance14)||defined($distance15)||defined($distance16)||defined($distance17)) && !(defined($distance19)||defined($distance20)||defined($distance21)||defined($distance22)) ) {
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri13)" if $http_uri03 && $http_uri08 && $http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
  }
  elsif( !(defined($distance9)||defined($distance10)||defined($distance11)||defined($distance12)) && !(defined($distance14)||defined($distance15)||defined($distance16)||defined($distance17)) && !(defined($distance19)||defined($distance20)||defined($distance21)||defined($distance22)) ) {
   if( $http_uri03 && $http_uri08 && $http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73 && (( $http_uri03 !~ /\\x|^\^|\$$/ ) or ( $http_uri08 !~ /\\x|^\^|\$$/ ) or ( $http_uri13 !~ /\\x|^\^|\$$/ )) )
   {
    @tableauuri1 = ( $http_uri03, $http_uri08, $http_uri13 ) if $http_uri03 && $http_uri08 && $http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
    my $tableauuri1index=0;
    foreach( @tableauuri1 )
    {
     $tableauuri1[$tableauuri1index++] =~ s/\\(?!x)//g;
     if( $_ =~ /\\x|^\^|\$$/ ) { undef @tableauuri1 }
    }
   }
   else
   {
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri13|$http_uri03.*$http_uri13.*$http_uri08|$http_uri13.*$http_uri08.*$http_uri03|$http_uri08.*$http_uri13.*$http_uri03)" if $http_uri03 && $http_uri08 && $http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri18|$http_uri03.*$http_uri18.*$http_uri08|$http_uri18.*$http_uri08.*$http_uri03|$http_uri08.*$http_uri18.*$http_uri03)" if $http_uri03 && $http_uri08 && $http_uri18 && !$http_uri13 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri23|$http_uri03.*$http_uri23.*$http_uri08|$http_uri23.*$http_uri08.*$http_uri03|$http_uri08.*$http_uri23.*$http_uri03)" if $http_uri03 && $http_uri08 && $http_uri23 && !$http_uri13 && !$http_uri18 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri28|$http_uri03.*$http_uri28.*$http_uri08|$http_uri28.*$http_uri08.*$http_uri03|$http_uri08.*$http_uri28.*$http_uri03)" if $http_uri03 && $http_uri08 && $http_uri28 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri33|$http_uri03.*$http_uri33.*$http_uri08|$http_uri33.*$http_uri08.*$http_uri03|$http_uri08.*$http_uri33.*$http_uri03)" if $http_uri03 && $http_uri08 && $http_uri33 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri38|$http_uri03.*$http_uri38.*$http_uri08|$http_uri38.*$http_uri08.*$http_uri03|$http_uri08.*$http_uri38.*$http_uri03)" if $http_uri03 && $http_uri08 && $http_uri38 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri43|$http_uri03.*$http_uri43.*$http_uri08|$http_uri43.*$http_uri08.*$http_uri03|$http_uri08.*$http_uri43.*$http_uri03)" if $http_uri03 && $http_uri08 && $http_uri43 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri48|$http_uri03.*$http_uri48.*$http_uri08|$http_uri48.*$http_uri08.*$http_uri03|$http_uri08.*$http_uri48.*$http_uri03)" if $http_uri03 && $http_uri08 && $http_uri48 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri53|$http_uri03.*$http_uri53.*$http_uri08|$http_uri53.*$http_uri08.*$http_uri03|$http_uri08.*$http_uri53.*$http_uri03)" if $http_uri03 && $http_uri08 && $http_uri53 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri58|$http_uri03.*$http_uri58.*$http_uri08|$http_uri58.*$http_uri08.*$http_uri03|$http_uri08.*$http_uri58.*$http_uri03)" if $http_uri03 && $http_uri08 && $http_uri58 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri63|$http_uri03.*$http_uri63.*$http_uri08|$http_uri63.*$http_uri08.*$http_uri03|$http_uri08.*$http_uri63.*$http_uri03)" if $http_uri03 && $http_uri08 && $http_uri63 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*$http_uri08.*$pcre_uri73|$http_uri03.*$pcre_uri73.*$http_uri08|$pcre_uri73.*$http_uri08.*$http_uri03|$http_uri08.*$pcre_uri73.*$http_uri03)" if $http_uri03 && $http_uri08 && $pcre_uri73 && !$http_uri13 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63;
   }
  }

  # four uri
  if( (defined($distance9)||defined($distance10)||defined($distance11)||defined($distance12)) && (defined($distance14)||defined($distance15)||defined($distance16)||defined($distance17)) && (defined($distance19)||defined($distance20)||defined($distance21)||defined($distance22)) ) {
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri13.*$http_uri18)" if $http_uri03 && $http_uri08 && $http_uri13 && $http_uri18;

  } elsif( !(defined($distance9)||defined($distance10)||defined($distance11)||defined($distance12)) && !(defined($distance14)||defined($distance15)||defined($distance16)||defined($distance17)) && !(defined($distance19)||defined($distance20)||defined($distance21)||defined($distance22)) ) {
   if( $http_uri03 && $http_uri08 && $http_uri13 && $http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73 && (( $http_uri03 !~ /\\x|^\^|\$$/ ) or ( $http_uri08 !~ /\\x|^\^|\$$/ ) or ( $http_uri13 !~ /\\x|^\^|\$$/ ) or ( $http_uri18 !~ /\\x|^\^|\$$/ )) )
   {
    @tableauuri1 = ( $http_uri03, $http_uri08, $http_uri13, $http_uri18 ) if $http_uri03 && $http_uri08 && $http_uri13 && $http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
    my $tableauuri1index=0;
    foreach( @tableauuri1 )
    {
     $tableauuri1[$tableauuri1index++] =~ s/\\(?!x)//g;
     if( $_ =~ /\\x|^\^|\$$/ ) { undef @tableauuri1 }
    }
   }
   else
   {
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri13.*$http_uri18|$http_uri03.*$http_uri08.*$http_uri18.*$http_uri13|$http_uri03.*$http_uri13.*$http_uri08.*$http_uri18|$http_uri03.*$http_uri13.*$http_uri18.*$http_uri08|$http_uri08.*$http_uri13.*$http_uri18.*$http_uri03|$http_uri08.*$http_uri13.*$http_uri03.*$http_uri18|$http_uri08.*$http_uri03.*$http_uri13.*$http_uri18|$http_uri08.*$http_uri03.*$http_uri18.*$http_uri13|$http_uri13.*$http_uri03.*$http_uri08.*$http_uri18|$http_uri13.*$http_uri03.*$http_uri18.*$http_uri08|$http_uri13.*$http_uri08.*$http_uri18.*$http_uri03|$http_uri13.*$http_uri08.*$http_uri03.*$http_uri18|$http_uri18.*$http_uri03.*$http_uri08.*$http_uri13|$http_uri18.*$http_uri03.*$http_uri13.*$http_uri08|$http_uri18.*$http_uri13.*$http_uri03.*$http_uri08|$http_uri18.*$http_uri13.*$http_uri08.*$http_uri03)" if $http_uri03 && $http_uri08 && $http_uri13 && $http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri13.*$http_uri23|$http_uri03.*$http_uri08.*$http_uri23.*$http_uri13|$http_uri03.*$http_uri13.*$http_uri08.*$http_uri23|$http_uri03.*$http_uri13.*$http_uri23.*$http_uri08|$http_uri08.*$http_uri13.*$http_uri23.*$http_uri03|$http_uri08.*$http_uri13.*$http_uri03.*$http_uri23|$http_uri08.*$http_uri03.*$http_uri13.*$http_uri23|$http_uri08.*$http_uri03.*$http_uri23.*$http_uri13|$http_uri13.*$http_uri03.*$http_uri08.*$http_uri23|$http_uri13.*$http_uri03.*$http_uri23.*$http_uri08|$http_uri13.*$http_uri08.*$http_uri23.*$http_uri03|$http_uri13.*$http_uri08.*$http_uri03.*$http_uri23|$http_uri23.*$http_uri03.*$http_uri08.*$http_uri13|$http_uri23.*$http_uri03.*$http_uri13.*$http_uri08|$http_uri23.*$http_uri13.*$http_uri03.*$http_uri08|$http_uri23.*$http_uri13.*$http_uri08.*$http_uri03)" if $http_uri03 && $http_uri08 && $http_uri13 && $http_uri23 && !$http_uri18 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri13.*$http_uri28|$http_uri03.*$http_uri08.*$http_uri28.*$http_uri13|$http_uri03.*$http_uri13.*$http_uri08.*$http_uri28|$http_uri03.*$http_uri13.*$http_uri28.*$http_uri08|$http_uri08.*$http_uri13.*$http_uri28.*$http_uri03|$http_uri08.*$http_uri13.*$http_uri03.*$http_uri28|$http_uri08.*$http_uri03.*$http_uri13.*$http_uri28|$http_uri08.*$http_uri03.*$http_uri28.*$http_uri13|$http_uri13.*$http_uri03.*$http_uri08.*$http_uri28|$http_uri13.*$http_uri03.*$http_uri28.*$http_uri08|$http_uri13.*$http_uri08.*$http_uri28.*$http_uri03|$http_uri13.*$http_uri08.*$http_uri03.*$http_uri28|$http_uri28.*$http_uri03.*$http_uri08.*$http_uri13|$http_uri28.*$http_uri03.*$http_uri13.*$http_uri08|$http_uri28.*$http_uri13.*$http_uri03.*$http_uri08|$http_uri28.*$http_uri13.*$http_uri08.*$http_uri03)" if $http_uri03 && $http_uri08 && $http_uri13 && $http_uri28 && !$http_uri18 && !$http_uri23 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri13.*$http_uri33|$http_uri03.*$http_uri08.*$http_uri33.*$http_uri13|$http_uri03.*$http_uri13.*$http_uri08.*$http_uri33|$http_uri03.*$http_uri13.*$http_uri33.*$http_uri08|$http_uri08.*$http_uri13.*$http_uri33.*$http_uri03|$http_uri08.*$http_uri13.*$http_uri03.*$http_uri33|$http_uri08.*$http_uri03.*$http_uri13.*$http_uri33|$http_uri08.*$http_uri03.*$http_uri33.*$http_uri13|$http_uri13.*$http_uri03.*$http_uri08.*$http_uri33|$http_uri13.*$http_uri03.*$http_uri33.*$http_uri08|$http_uri13.*$http_uri08.*$http_uri33.*$http_uri03|$http_uri13.*$http_uri08.*$http_uri03.*$http_uri33|$http_uri33.*$http_uri03.*$http_uri08.*$http_uri13|$http_uri33.*$http_uri03.*$http_uri13.*$http_uri08|$http_uri33.*$http_uri13.*$http_uri03.*$http_uri08|$http_uri33.*$http_uri13.*$http_uri08.*$http_uri03)" if $http_uri03 && $http_uri08 && $http_uri13 && $http_uri33 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri13.*$http_uri38|$http_uri03.*$http_uri08.*$http_uri38.*$http_uri13|$http_uri03.*$http_uri13.*$http_uri08.*$http_uri38|$http_uri03.*$http_uri13.*$http_uri38.*$http_uri08|$http_uri08.*$http_uri13.*$http_uri38.*$http_uri03|$http_uri08.*$http_uri13.*$http_uri03.*$http_uri38|$http_uri08.*$http_uri03.*$http_uri13.*$http_uri38|$http_uri08.*$http_uri03.*$http_uri38.*$http_uri13|$http_uri13.*$http_uri03.*$http_uri08.*$http_uri38|$http_uri13.*$http_uri03.*$http_uri38.*$http_uri08|$http_uri13.*$http_uri08.*$http_uri38.*$http_uri03|$http_uri13.*$http_uri08.*$http_uri03.*$http_uri38|$http_uri38.*$http_uri03.*$http_uri08.*$http_uri13|$http_uri38.*$http_uri03.*$http_uri13.*$http_uri08|$http_uri38.*$http_uri13.*$http_uri03.*$http_uri08|$http_uri38.*$http_uri13.*$http_uri08.*$http_uri03)" if $http_uri03 && $http_uri08 && $http_uri13 && $http_uri38 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri13.*$http_uri43|$http_uri03.*$http_uri08.*$http_uri43.*$http_uri13|$http_uri03.*$http_uri13.*$http_uri08.*$http_uri43|$http_uri03.*$http_uri13.*$http_uri43.*$http_uri08|$http_uri08.*$http_uri13.*$http_uri43.*$http_uri03|$http_uri08.*$http_uri13.*$http_uri03.*$http_uri43|$http_uri08.*$http_uri03.*$http_uri13.*$http_uri43|$http_uri08.*$http_uri03.*$http_uri43.*$http_uri13|$http_uri13.*$http_uri03.*$http_uri08.*$http_uri43|$http_uri13.*$http_uri03.*$http_uri43.*$http_uri08|$http_uri13.*$http_uri08.*$http_uri43.*$http_uri03|$http_uri13.*$http_uri08.*$http_uri03.*$http_uri43|$http_uri43.*$http_uri03.*$http_uri08.*$http_uri13|$http_uri43.*$http_uri03.*$http_uri13.*$http_uri08|$http_uri43.*$http_uri13.*$http_uri03.*$http_uri08|$http_uri43.*$http_uri13.*$http_uri08.*$http_uri03)" if $http_uri03 && $http_uri08 && $http_uri13 && $http_uri43 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri13.*$http_uri48|$http_uri03.*$http_uri08.*$http_uri48.*$http_uri13|$http_uri03.*$http_uri13.*$http_uri08.*$http_uri48|$http_uri03.*$http_uri13.*$http_uri48.*$http_uri08|$http_uri08.*$http_uri13.*$http_uri48.*$http_uri03|$http_uri08.*$http_uri13.*$http_uri03.*$http_uri48|$http_uri08.*$http_uri03.*$http_uri13.*$http_uri48|$http_uri08.*$http_uri03.*$http_uri48.*$http_uri13|$http_uri13.*$http_uri03.*$http_uri08.*$http_uri48|$http_uri13.*$http_uri03.*$http_uri48.*$http_uri08|$http_uri13.*$http_uri08.*$http_uri48.*$http_uri03|$http_uri13.*$http_uri08.*$http_uri03.*$http_uri48|$http_uri48.*$http_uri03.*$http_uri08.*$http_uri13|$http_uri48.*$http_uri03.*$http_uri13.*$http_uri08|$http_uri48.*$http_uri13.*$http_uri03.*$http_uri08|$http_uri48.*$http_uri13.*$http_uri08.*$http_uri03)" if $http_uri03 && $http_uri08 && $http_uri13 && $http_uri48 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri13.*$http_uri53|$http_uri03.*$http_uri08.*$http_uri53.*$http_uri13|$http_uri03.*$http_uri13.*$http_uri08.*$http_uri53|$http_uri03.*$http_uri13.*$http_uri53.*$http_uri08|$http_uri08.*$http_uri13.*$http_uri53.*$http_uri03|$http_uri08.*$http_uri13.*$http_uri03.*$http_uri53|$http_uri08.*$http_uri03.*$http_uri13.*$http_uri53|$http_uri08.*$http_uri03.*$http_uri53.*$http_uri13|$http_uri13.*$http_uri03.*$http_uri08.*$http_uri53|$http_uri13.*$http_uri03.*$http_uri53.*$http_uri08|$http_uri13.*$http_uri08.*$http_uri53.*$http_uri03|$http_uri13.*$http_uri08.*$http_uri03.*$http_uri53|$http_uri53.*$http_uri03.*$http_uri08.*$http_uri13|$http_uri53.*$http_uri03.*$http_uri13.*$http_uri08|$http_uri53.*$http_uri13.*$http_uri03.*$http_uri08|$http_uri53.*$http_uri13.*$http_uri08.*$http_uri03)" if $http_uri03 && $http_uri08 && $http_uri13 && $http_uri53 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri13.*$http_uri58|$http_uri03.*$http_uri08.*$http_uri58.*$http_uri13|$http_uri03.*$http_uri13.*$http_uri08.*$http_uri58|$http_uri03.*$http_uri13.*$http_uri58.*$http_uri08|$http_uri08.*$http_uri13.*$http_uri58.*$http_uri03|$http_uri08.*$http_uri13.*$http_uri03.*$http_uri58|$http_uri08.*$http_uri03.*$http_uri13.*$http_uri58|$http_uri08.*$http_uri03.*$http_uri58.*$http_uri13|$http_uri13.*$http_uri03.*$http_uri08.*$http_uri58|$http_uri13.*$http_uri03.*$http_uri58.*$http_uri08|$http_uri13.*$http_uri08.*$http_uri58.*$http_uri03|$http_uri13.*$http_uri08.*$http_uri03.*$http_uri58|$http_uri58.*$http_uri03.*$http_uri08.*$http_uri13|$http_uri58.*$http_uri03.*$http_uri13.*$http_uri08|$http_uri58.*$http_uri13.*$http_uri03.*$http_uri08|$http_uri58.*$http_uri13.*$http_uri08.*$http_uri03)" if $http_uri03 && $http_uri08 && $http_uri13 && $http_uri58 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri63 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri13.*$http_uri63|$http_uri03.*$http_uri08.*$http_uri63.*$http_uri13|$http_uri03.*$http_uri13.*$http_uri08.*$http_uri63|$http_uri03.*$http_uri13.*$http_uri63.*$http_uri08|$http_uri08.*$http_uri13.*$http_uri63.*$http_uri03|$http_uri08.*$http_uri13.*$http_uri03.*$http_uri63|$http_uri08.*$http_uri03.*$http_uri13.*$http_uri63|$http_uri08.*$http_uri03.*$http_uri63.*$http_uri13|$http_uri13.*$http_uri03.*$http_uri08.*$http_uri63|$http_uri13.*$http_uri03.*$http_uri63.*$http_uri08|$http_uri13.*$http_uri08.*$http_uri63.*$http_uri03|$http_uri13.*$http_uri08.*$http_uri03.*$http_uri63|$http_uri63.*$http_uri03.*$http_uri08.*$http_uri13|$http_uri63.*$http_uri03.*$http_uri13.*$http_uri08|$http_uri63.*$http_uri13.*$http_uri03.*$http_uri08|$http_uri63.*$http_uri13.*$http_uri08.*$http_uri03)" if $http_uri03 && $http_uri08 && $http_uri13 && $http_uri63 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$pcre_uri73;
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri13.*$pcre_uri73|$http_uri03.*$http_uri08.*$pcre_uri73.*$http_uri13|$http_uri03.*$http_uri13.*$http_uri08.*$pcre_uri73|$http_uri03.*$http_uri13.*$pcre_uri73.*$http_uri08|$http_uri08.*$http_uri13.*$pcre_uri73.*$http_uri03|$http_uri08.*$http_uri13.*$http_uri03.*$pcre_uri73|$http_uri08.*$http_uri03.*$http_uri13.*$pcre_uri73|$http_uri08.*$http_uri03.*$pcre_uri73.*$http_uri13|$http_uri13.*$http_uri03.*$http_uri08.*$pcre_uri73|$http_uri13.*$http_uri03.*$pcre_uri73.*$http_uri08|$http_uri13.*$http_uri08.*$pcre_uri73.*$http_uri03|$http_uri13.*$http_uri08.*$http_uri03.*$pcre_uri73|$pcre_uri73.*$http_uri03.*$http_uri08.*$http_uri13|$pcre_uri73.*$http_uri03.*$http_uri13.*$http_uri08|$pcre_uri73.*$http_uri13.*$http_uri03.*$http_uri08|$pcre_uri73.*$http_uri13.*$http_uri08.*$http_uri03)" if $http_uri03 && $http_uri08 && $http_uri13 && $pcre_uri73 && !$http_uri18 && !$http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63;
   }
  }

  # five uri
  if( (defined($distance9)||defined($distance10)||defined($distance11)||defined($distance12)) && (defined($distance14)||defined($distance15)||defined($distance16)||defined($distance17)) && (defined($distance19)||defined($distance20)||defined($distance21)||defined($distance22)) && (defined($distance24)||defined($distance25)||defined($distance26)||defined($distance27)) ) {
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri13.*$http_uri18.*$http_uri23)" if $http_uri03 && $http_uri08 && $http_uri13 && $http_uri18 && $http_uri23;
  }
  elsif( !(defined($distance9)||defined($distance10)||defined($distance11)||defined($distance12)) && !(defined($distance14)||defined($distance15)||defined($distance16)||defined($distance17)) && !(defined($distance19)||defined($distance20)||defined($distance21)||defined($distance22)) && !(defined($distance24)||defined($distance25)||defined($distance26)||defined($distance27)) ) {
   if( $http_uri03 && $http_uri08 && $http_uri13 && $http_uri18 && $http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73 && (( $http_uri03 !~ /\\x|^\^|\$$/ ) or ( $http_uri08 !~ /\\x|^\^|\$$/ ) or ( $http_uri13 !~ /\\x|^\^|\$$/ ) or ( $http_uri18 !~ /\\x|^\^|\$$/ ) or ( $http_uri23 !~ /\\x|^\^|\$$/ )) )
   {
    @tableauuri1 = ( $http_uri03, $http_uri08, $http_uri13, $http_uri18, $http_uri23 ) if $http_uri03 && $http_uri08 && $http_uri13 && $http_uri18 && $http_uri23 && !$http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
    my $tableauuri1index=0;
    foreach( @tableauuri1 )
    {
     $tableauuri1[$tableauuri1index++] =~ s/\\(?!x)//g;
     if( $_ =~ /\\x|^\^|\$$/ ) { undef @tableauuri1 }
    }
   }
  }

  # six uri
  if( (defined($distance9)||defined($distance10)||defined($distance11)||defined($distance12)) && (defined($distance14)||defined($distance15)||defined($distance16)||defined($distance17)) && (defined($distance19)||defined($distance20)||defined($distance21)||defined($distance22)) && (defined($distance24)||defined($distance25)||defined($distance26)||defined($distance27)) && (defined($distance29)||defined($distance30)||defined($distance31)||defined($distance32)) ) {
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri13.*$http_uri18.*$http_uri23.*$http_uri28)" if $http_uri03 && $http_uri08 && $http_uri13 && $http_uri18 && $http_uri23 && $http_uri28;
  }
  elsif( !(defined($distance9)||defined($distance10)||defined($distance11)||defined($distance12)) && !(defined($distance14)||defined($distance15)||defined($distance16)||defined($distance17)) && !(defined($distance19)||defined($distance20)||defined($distance21)||defined($distance22)) && !(defined($distance24)||defined($distance25)||defined($distance26)||defined($distance27)) && !(defined($distance29)||defined($distance30)||defined($distance31)||defined($distance32)) ) {
   if( $http_uri03 && $http_uri08 && $http_uri13 && $http_uri18 && $http_uri23 && $http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73 && (( $http_uri03 !~ /\\x|^\^|\$$/ ) or ( $http_uri08 !~ /\\x|^\^|\$$/ ) or ( $http_uri13 !~ /\\x|^\^|\$$/ ) or ( $http_uri18 !~ /\\x|^\^|\$$/ ) or ( $http_uri23 !~ /\\x|^\^|\$$/ ) or ( $http_uri28 !~ /\\x|^\^|\$$/ )) )
   {
    @tableauuri1 = ( $http_uri03, $http_uri08, $http_uri13, $http_uri18, $http_uri23, $http_uri28 ) if $http_uri03 && $http_uri08 && $http_uri13 && $http_uri18 && $http_uri23 && $http_uri28 && !$http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
    my $tableauuri1index=0;
    foreach( @tableauuri1 )
    {
     $tableauuri1[$tableauuri1index++] =~ s/\\(?!x)//g;
     if( $_ =~ /\\x|^\^|\$$/ ) { undef @tableauuri1 }
    }
   }
  }

  # seven uri
  if( (defined($distance9)||defined($distance10)||defined($distance11)||defined($distance12)) && (defined($distance14)||defined($distance15)||defined($distance16)||defined($distance17)) && (defined($distance19)||defined($distance20)||defined($distance21)||defined($distance22)) && (defined($distance24)||defined($distance25)||defined($distance26)||defined($distance27)) && (defined($distance29)||defined($distance30)||defined($distance31)||defined($distance32)) && (defined($distance34)||defined($distance35)||defined($distance36)||defined($distance37)) ) {
   $abc1= "(?:$http_uri03.*$http_uri08.*$http_uri13.*$http_uri18.*$http_uri23.*$http_uri28.*$http_uri33)" if $http_uri03 && $http_uri08 && $http_uri13 && $http_uri18 && $http_uri23 && $http_uri28 && $http_uri33;
  }
  elsif( (defined($distance9)||defined($distance10)||defined($distance11)||defined($distance12)) && (defined($distance14)||defined($distance15)||defined($distance16)||defined($distance17)) && (defined($distance19)||defined($distance20)||defined($distance21)||defined($distance22)) && (defined($distance24)||defined($distance25)||defined($distance26)||defined($distance27)) && (defined($distance29)||defined($distance30)||defined($distance31)||defined($distance32)) && (defined($distance34)||defined($distance35)||defined($distance36)||defined($distance37)) ) {
   if( $http_uri03 && $http_uri08 && $http_uri13 && $http_uri18 && $http_uri23 && $http_uri28 && $http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73 && (( $http_uri03 !~ /\\x|^\^|\$$/ ) or ( $http_uri08 !~ /\\x|^\^|\$$/ ) or ( $http_uri13 !~ /\\x|^\^|\$$/ ) or ( $http_uri18 !~ /\\x|^\^|\$$/ ) or ( $http_uri23 !~ /\\x|^\^|\$$/ ) or ( $http_uri28 !~ /\\x|^\^|\$$/ )) )
   {
    @tableauuri1 = ( $http_uri03, $http_uri08, $http_uri13, $http_uri18, $http_uri23, $http_uri28, $http_uri33 ) if $http_uri03 && $http_uri08 && $http_uri13 && $http_uri18 && $http_uri23 && $http_uri28 && $http_uri33 && !$http_uri38 && !$http_uri43 && !$http_uri48 && !$http_uri53 && !$http_uri58 && !$http_uri63 && !$pcre_uri73;
    my $tableauuri1index=0;
    foreach( @tableauuri1 )
    {
     $tableauuri1[$tableauuri1index++] =~ s/\\(?!x)//g;
     if( $_ =~ /\\x|^\^|\$$/ ) { undef @tableauuri1 }
    }
   }
  }

  # uri:
  my $abc1_nocase=0;
     $abc1_nocase=$http_urifast5    if $http_urifast5;
     $abc1_nocase=$http_urinocase5  if $http_urinocase5;
     $abc1_nocase=$http_urifast9    if $http_urifast9;
     $abc1_nocase=$http_urifast14   if $http_urifast14;
     $abc1_nocase=$http_urinocase12 if $http_urinocase12;
     $abc1_nocase=$http_urifast18   if $http_urifast18;
     $abc1_nocase=$http_urinocase15 if $http_urinocase15;
     $abc1_nocase=$http_urifast23   if $http_urifast23;
     $abc1_nocase=$http_urinocase19 if $http_urinocase19;
     $abc1_nocase=$http_urifast27   if $http_urifast27;
     $abc1_nocase=$http_urinocase22 if $http_urinocase22;
     $abc1_nocase=$http_urifast32   if $http_urifast32;
     $abc1_nocase=$http_urinocase26 if $http_urinocase26;
     $abc1_nocase=$http_urifast36   if $http_urifast36;
     $abc1_nocase=$http_urinocase29 if $http_urinocase29;
     $abc1_nocase=$http_urifast41   if $http_urifast41;
     $abc1_nocase=$http_urinocase33 if $http_urinocase33;
     $abc1_nocase=$http_urifast44   if $http_urifast44;
     $abc1_nocase=$http_urinocase36 if $http_urinocase36;
     $abc1_nocase=$http_urifast49   if $http_urifast49;
     $abc1_nocase=$http_urinocase40 if $http_urinocase40;
     $abc1_nocase=$http_urifast54   if $http_urifast54;
     $abc1_nocase=$http_urinocase43 if $http_urinocase43;
     $abc1_nocase=$http_urifast58   if $http_urifast58;
     $abc1_nocase=$http_urinocase47 if $http_urinocase47;
     $abc1_nocase=$http_urifast62   if $http_urifast62;
     $abc1_nocase=$http_urinocase50 if $http_urinocase50;
     $abc1_nocase=$http_urinocase54 if $http_urinocase54;
     $abc1_nocase=$http_urinocase57 if $http_urinocase57;
     $abc1_nocase=$http_urinocase61 if $http_urinocase61;
     $abc1_nocase=$http_urinocase64 if $http_urinocase64;
     $abc1_nocase=$http_urinocase68 if $http_urinocase68;
     $abc1_nocase=$http_urinocase71 if $http_urinocase71;
     $abc1_nocase=$http_urinocase75 if $http_urinocase75;
     $abc1_nocase=$http_urinocase78 if $http_urinocase78;
     $abc1_nocase=$http_urinocase82 if $http_urinocase82;
     $abc1_nocase=$http_urinocase85 if $http_urinocase85;
     $abc1_nocase=$http_urinocase89 if $http_urinocase89;
     $abc1_nocase=$http_urinocase92 if $http_urinocase92;

  # header:
  my $httppcreagent_nocase=0;
     $httppcreagent_nocase=$http_headernocase96 if $http_headernocase96;
     $httppcreagent_nocase=$http_headernocase99 if $http_headernocase99;
     $httppcreagent_nocase=$http_headerfast122  if $http_headerfast122;
     $httppcreagent_nocase=$http_headernocase123 if $http_headernocase123;
     $httppcreagent_nocase=$http_headerfast126  if $http_headerfast126;
     $httppcreagent_nocase=$http_headernocase127 if $http_headernocase127;
     $httppcreagent_nocase=$http_headerfast132  if $http_headerfast132;
     $httppcreagent_nocase=$http_headernocase104 if $http_headernocase104;
     $httppcreagent_nocase=$http_headerfast136  if $http_headerfast136;
     $httppcreagent_nocase=$http_headernocase107 if $http_headernocase107;

  if( $httpagentshort && $httppcreagent )
  {
   my $tempopcreagent = $httppcreagent;
   $tempopcreagent =~ s/\\//g;
   if( $httpagentshort eq $tempopcreagent )
   {
    print "tempopcreagent: $tempopcreagent\n" if $debug1;
    undef $httppcreagent;
    undef $tempopcreagent;
   }
  }

  print "httpuricourt1: $etmsg1, $httpuricourt\n" if $debug1 && $httpuricourt;
  print "httpurilong1: $etmsg1, @tableauuri1\n" if $debug1 && @tableauuri1;
  print "tableaupcreuri1: $etmsg1, $abc1\n" if $debug1 && $abc1;
  print "tableaupcreagent1: $etmsg1, $httppcreagent\n" if $debug1 && $httppcreagent;
  print "httpagentshort1: $etmsg1, $httpagentshort\n" if $debug1 && $httpagentshort;
  print "tableauhttpmethod1: $etmsg1, $http_method2\n" if $debug1 && $http_method2;
  print "tableaupcrereferer1: $etmsg1, $pcrereferer\n" if $debug1 && $pcrereferer;

  $hash{$etmsg1}{httpuricourt} = [ $httpuricourt ] if $httpuricourt;
  $hash{$etmsg1}{httpagentshort} = [ $httpagentshort ] if $httpagentshort;
  $hash{$etmsg1}{httpmethod} = [ $http_method2, $http_methodnocase3 ] if $http_method2;
  $hash{$etmsg1}{pcrereferer} = [ $pcrereferer ] if $pcrereferer;
  $hash{$etmsg1}{pcreuri} = [ $abc1, $abc1_nocase ] if $abc1;
  $hash{$etmsg1}{pcreagent} = [ $httppcreagent, $httppcreagent_nocase ] if $httppcreagent;
  $hash{$etmsg1}{httpurilong} = [ @tableauuri1 ] if @tableauuri1;

  next;
 }

 # begin uricontent
 elsif( $_=~ /^\s*alert\s+(?:udp|tcp)\s+\S+\s+\S+\s+\-\>\s+$category\s+\S+\s+\(\s*msg\:\s*\"([^\"]*?)\"\s*\;\s*(?:$flow1)?(?:$urilen1)?(?:$httpmethod)?(?:$negateuricontent1)?\s*uricontent\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:$negateuricontent1)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*\s*http_header\;(?:$contentoptions1)*(?:$negateuricontent1)?)?(?:\s*uricontent\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:\s*uricontent\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:\s*(?:uri)?content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*)?(?:$negateuricontent1)?(?:$pcreuri)?(?:$extracontentoptions)?$referencesidrev$/ )
 {
  my $etmsg1=$1;
  my $http_method2=0;
  my $http_methodnocase3=0;
  print "brut2: $_\n" if $debug1;
  #print "here2: 1: $1, 2: $2, 3: $3, 4: $4, 5: $5, 6: $6, 7: $7, 8: $8, 9: $9, 10: $10, 11: $11, 12: $12, 13: $13, 14: $14, 15: $15, 16: $16, 17: $17, 18: $18, 19: $19, 20: $20, 21: $21, 22: $22, 23: $23, 24: $24, 25: $25, 26: $26, 27: $27, 28: $28, 29: $29, 30: $30, 31: $31, 32: $32, 33: $33\n" if $debug1;

     $http_method2=$2 if $2;
     $http_methodnocase3=$3 if $3;

  my $http_uri03=$4 if $4;		# 4
  my $http_urifast5=$5 if $5;
  my $http_urinocase5=$6 if $6;		# 5
  my $http_header06=$8 if $8;		# 8
  my $http_headernocase9=$9 if $9;	# 9
  my $http_headernocase12=$12 if $12;	# 12
  my $http_uri11=$18 if $18;		# 15
  my $http_urifast19=$19 if $19;
  my $http_urinocase16=$20 if $20;	# 16
  my $http_uri14=$23 if $23;		# 19
  my $http_urifast24=$24 if $24;
  my $http_urinocase20=$25 if $25;	# 20
  my $http_uri17=$28 if $28;		# 23
  my $http_urifast29=$29 if $29;
  my $http_urinocase23=$30 if $30;	# 24
  my $pcre_uri20=$33 if $33;		# 27

  # check what is http_uri best length ?
  my $httpuricourt=0;
  my $http_uri03_length=0;
  my $http_uri11_length=0;
  my $http_uri14_length=0;
  my $http_uri17_length=0;
  $http_uri03_length=length($http_uri03) if $http_uri03;
  $http_uri11_length=length($http_uri11) if $http_uri11;
  $http_uri14_length=length($http_uri14) if $http_uri14;
  $http_uri17_length=length($http_uri17) if $http_uri17;
  if( $http_uri03_length >= $http_uri11_length && $http_uri03_length >= $http_uri14_length && $http_uri03_length >= $http_uri17_length )
  { $httpuricourt=$http_uri03; }
  elsif( $http_uri11_length >= $http_uri03_length && $http_uri11_length >= $http_uri14_length && $http_uri11_length >= $http_uri17_length )
  { $httpuricourt=$http_uri11; }
  elsif( $http_uri14_length >= $http_uri03_length && $http_uri14_length >= $http_uri11_length && $http_uri14_length >= $http_uri17_length )
  { $httpuricourt=$http_uri14; }
  elsif( $http_uri17_length >= $http_uri03_length && $http_uri17_length >= $http_uri11_length && $http_uri17_length >= $http_uri14_length )
  { $httpuricourt=$http_uri17; }

  $http_uri03 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri03; # (
  $http_uri03 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri03; # )
  $http_uri03 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri03; # *
  $http_uri03 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri03; # +
  $http_uri03 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri03; # -
  $http_uri03 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri03; # .
  $http_uri03 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri03; # /
  $http_uri03 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri03; # ?
  $http_uri03 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri03; # [
  $http_uri03 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri03; # ]
  $http_uri03 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri03; # ^
  $http_uri03 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri03; # {
  $http_uri03 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri03; # }
  $http_header06 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_header06; # (
  $http_header06 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_header06; # )
  $http_header06 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_header06; # *
  $http_header06 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_header06; # +
  $http_header06 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_header06; # -
  $http_header06 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_header06; # .
  $http_header06 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_header06; # /
  $http_header06 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_header06; # ?
  $http_header06 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_header06; # [
  $http_header06 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_header06; # ]
  #$http_header06 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_header06; # ^
  $http_header06 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_header06; # {
  $http_header06 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_header06; # }
  $http_uri11 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri11; # (
  $http_uri11 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri11; # )
  $http_uri11 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri11; # *
  $http_uri11 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri11; # +
  $http_uri11 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri11; # -
  $http_uri11 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri11; # .
  $http_uri11 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri11; # /
  $http_uri11 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri11; # ?
  $http_uri11 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri11; # [
  $http_uri11 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri11; # ]
  $http_uri11 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri11; # ^
  $http_uri11 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri11; # {
  $http_uri11 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri11; # }
  $http_uri14 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri14; # (
  $http_uri14 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri14; # )
  $http_uri14 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri14; # *
  $http_uri14 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri14; # +
  $http_uri14 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri14; # -
  $http_uri14 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri14; # .
  $http_uri14 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri14; # /
  $http_uri14 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri14; # ?
  $http_uri14 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri14; # [
  $http_uri14 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri14; # ]
  $http_uri14 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri14; # ^
  $http_uri14 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri14; # {
  $http_uri14 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri14; # }
  $http_uri17 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri17; # (
  $http_uri17 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri17; # )
  $http_uri17 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri17; # *
  $http_uri17 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri17; # +
  $http_uri17 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri17; # -
  $http_uri17 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri17; # .
  $http_uri17 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri17; # /
  $http_uri17 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri17; # ?
  $http_uri17 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri17; # [
  $http_uri17 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri17; # ]
  $http_uri17 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri17; # ^
  $http_uri17 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri17; # {
  $http_uri17 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri17; # }
  #$pcre_uri20 =~ s/(?<!\x5C)\x24//g         if $pcre_uri20; # $

  while($http_uri03 && $http_uri03=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_uri03=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  while($http_header06 && $http_header06=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_header06=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  while($http_uri11 && $http_uri11=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_uri11=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  while($http_uri14 && $http_uri14=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_uri14=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  while($http_uri17 && $http_uri17=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_uri17=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  # ne pas faire d'echappement sur la pcre ($pcre_uri20)
  my $abc1=0;
  my $httppcreagent=0;
  my $httpagentshort=0;
  my $pcrereferer=0;
  my @tableauuri1;

     if( $http_header06 && $http_header06 =~ s/\QUser\-Agent\x3A\x20\E(?!$)/^/i ) { }
  elsif( $http_header06 && $http_header06 =~ s/\QUser\-Agent\x3A\x20\E$/^/i ) { undef($http_header06) }
  elsif( $http_header06 && $http_header06 =~ s/\QUser\-Agent\x3A \E(?!$)/^/i ) { }
  elsif( $http_header06 && $http_header06 =~  /\QUser\-Agent\x3A \E$/i ) { undef($http_header06) }
  elsif( $http_header06 && $http_header06 =~ s/\QUser-Agent\x3A \E(?!$)/^/i ) { }
  elsif( $http_header06 && $http_header06 =~  /\QUser-Agent\x3A \E$/i ) { undef($http_header06) }
  elsif( $http_header06 && $http_header06 =~ s/\QUser\-Agent\: \E(?!$)/^/i ) { }
  elsif( $http_header06 && $http_header06 =~  /\QUser\-Agent\: \E$/i ) { undef($http_header06) }
  elsif( $http_header06 && $http_header06 =~ s/\QUser-Agent\: \E(?!$)/^/i ) { }
  elsif( $http_header06 && $http_header06 =~  /\QUser-Agent\: \E$/i ) { undef($http_header06) }
  elsif( $http_header06 && $http_header06 =~ s/\QUser\-Agent\x3A\E(?!$)/^/i ) { }
  elsif( $http_header06 && $http_header06 =~  /\QUser\-Agent\x3A\E$/i ) { undef($http_header06) }
  elsif( $http_header06 && $http_header06 =~ s/\QUser-Agent\x3A\E(?!$)/^/i ) { }
  elsif( $http_header06 && $http_header06 =~  /\QUser-Agent\x3A\E$/i ) { undef($http_header06) }
  elsif( $http_header06 && $http_header06 =~ s/\QUser\-Agent\:\E(?!$)/^/i ) { }
  elsif( $http_header06 && $http_header06 =~  /\QUser\-Agent\:\E$/i ) { undef($http_header06) }
  elsif( $http_header06 && $http_header06 =~ s/\QUser-Agent\:\E(?!$)/^/i ) { }
  elsif( $http_header06 && $http_header06 =~  /\QUser-Agent\:\E$/i ) { undef($http_header06) }
                           $http_header06 =~ s/\Q\x0D\x0A\E/\$/i if $http_header06; # http_header, \x0D\x0A
     if( $http_header06 && $http_header06 =~ s/\QReferer\x3A\x20\E/^/i ) { $pcrereferer = $http_header06; undef $http_header06 }
  elsif( $http_header06 && $http_header06 =~ s/\QReferer\x3A \E/^/i ) { $pcrereferer = $http_header06; undef $http_header06 }

  if( $pcre_uri20 )
  {
   $pcre_uri20 =~ s/^\^\\\//\^(?:https?\\\:\\\/\\\/)?[^\\\/]*?\\\//i;
   $pcre_uri20 =~ s/^\^\\x2F/\^(?:https?\\\:\\\/\\\/)?[^\\\/]*?\\x2F/i;
  }

  # http_user_agent short
  if( $http_header06 )
  {
   $httpagentshort= "$http_header06" if $http_header06;
  }
  while( $httpagentshort =~ /\\x(..)/g )
  {
   my $tempochr=chr(hex("$1"));
   $httpagentshort =~ s/\\x(..)/$tempochr/;
  }
  $httpagentshort =~ s/(?:\\|\^|\$)//g;

  if( $pcre_uri20 && $http_uri03 && $pcre_uri20=~/\Q$http_uri03\E/i ) {
   undef $http_uri03;
   print "ok trouver grep3a\n" if $debug1;
  }
  elsif( $pcre_uri20 && $http_uri03 && $http_uri03=~s/\&/\\x26/g && $pcre_uri20=~/\Q$http_uri03\E/i ) {
   undef $http_uri03;
   print "ok trouver grep3b\n" if $debug1;
  }
  elsif( $pcre_uri20 && $http_uri03 && $http_uri03=~s/\=/\\x3D/g && $pcre_uri20=~/\Q$http_uri03\E/i ) {
   undef $http_uri03;
   print "ok trouver grep3c\n" if $debug1;
  }
  if( $pcre_uri20 && $http_header06 && $pcre_uri20=~/\Q$http_header06\E/i ) {
   undef $http_header06;
   print "ok trouver grep6a\n" if $debug1;
  }
  elsif( $pcre_uri20 && $http_header06 && $http_header06=~s/\&/\\x26/g && $pcre_uri20=~/\Q$http_header06\E/i ) {
   undef $http_header06;
   print "ok trouver grep6b\n" if $debug1;
  }
  elsif( $pcre_uri20 && $http_header06 && $http_header06=~s/\=/\\x3D/g && $pcre_uri20=~/\Q$http_header06\E/i ) {
   undef $http_header06;
   print "ok trouver grep6c\n" if $debug1;
  }
  if( $pcre_uri20 && $http_uri11 && $pcre_uri20=~/\Q$http_uri11\E/i ) {
   undef $http_uri11;
   print "ok trouver grep11a\n" if $debug1;
  }
  elsif( $pcre_uri20 && $http_uri11 && $http_uri11=~s/\&/\\x26/g && $pcre_uri20=~/\Q$http_uri11\E/i ) {
   undef $http_uri11;
   print "ok trouver grep11b\n" if $debug1;
  }
  elsif( $pcre_uri20 && $http_uri11 && $http_uri11=~s/\=/\\x3D/g && $pcre_uri20=~/\Q$http_uri11\E/i ) {
   undef $http_uri11;
   print "ok trouver grep11c\n" if $debug1;
  }
  if( $pcre_uri20 && $http_uri14 && $pcre_uri20=~/\Q$http_uri14\E/i ) {
   undef $http_uri14;
   print "ok trouver grep14a\n" if $debug1;
  }
  elsif( $pcre_uri20 && $http_uri14 && $http_uri14=~s/\&/\\x26/g && $pcre_uri20=~/\Q$http_uri14\E/i ) {
   undef $http_uri14;
   print "ok trouver grep14b\n" if $debug1;
  }
  elsif( $pcre_uri20 && $http_uri14 && $http_uri14=~s/\=/\\x3D/g && $pcre_uri20=~/\Q$http_uri14\E/i ) {
   undef $http_uri14;
   print "ok trouver grep14c\n" if $debug1;
  }
  if( $pcre_uri20 && $http_uri17 && $pcre_uri20=~/\Q$http_uri17\E/i ) {
   undef $http_uri17;
   print "ok trouver grep17a\n" if $debug1;
  }
  elsif( $pcre_uri20 && $http_uri17 && $http_uri17=~s/\&/\\x26/g && $pcre_uri20=~/\Q$http_uri17\E/i ) {
   undef $http_uri17;
   print "ok trouver grep17b\n" if $debug1;
  }
  elsif( $pcre_uri20 && $http_uri17 && $http_uri17=~s/\=/\\x3D/g && $pcre_uri20=~/\Q$http_uri17\E/i ) {
   undef $http_uri17;
   print "ok trouver grep17c\n" if $debug1;
  }

  # one uri
  #$abc1= "$http_uri03" if $http_uri03 && !$http_uri11 && !$http_uri14 && !$http_uri17 && !$pcre_uri20;
  #$abc1= "$http_uri11" if $http_uri11 && !$http_uri03 && !$http_uri14 && !$http_uri17 && !$pcre_uri20;
  #$abc1= "$http_uri14" if $http_uri14 && !$http_uri03 && !$http_uri11 && !$http_uri17 && !$pcre_uri20;
  #$abc1= "$http_uri17" if $http_uri17 && !$http_uri03 && !$http_uri11 && !$http_uri14 && !$pcre_uri20;
  $abc1= "$pcre_uri20" if $pcre_uri20 && !$http_uri03 && !$http_uri11 && !$http_uri14 && !$http_uri17;

  # one header
  #$httppcreagent= "$http_header06" if $http_header06;

  # two uri
  if( $http_uri03 && $http_uri11 && !$http_uri14 && !$http_uri17 && !$pcre_uri20 && (( $http_uri03 !~ /\\x|^\^|\$$/ ) or ( $http_uri11 !~ /\\x|^\^|\$$/ )) )
  {
   @tableauuri1 = ( $http_uri03, $http_uri11 ) if $http_uri03 && $http_uri11 && !$http_uri14 && !$http_uri17 && !$pcre_uri20;
   my $tableauuri1index=0;
   foreach( @tableauuri1 )
   {
    $tableauuri1[$tableauuri1index++] =~ s/\\(?!x)//g;
    if( $_ =~ /\\x|^\^|\$$/ ) { undef @tableauuri1 }
   }
  }
  else
  {
   $abc1= "(?:$http_uri03.*?$http_uri11|$http_uri11.*?$http_uri03)" if $http_uri03 && $http_uri11 && !$http_uri14 && !$http_uri17 && !$pcre_uri20;
  }

  if( $http_uri03 && $http_uri14 && !$http_uri11 && !$http_uri17 && !$pcre_uri20 && (( $http_uri03 !~ /\\x|^\^|\$$/ ) or ( $http_uri14 !~ /\\x|^\^|\$$/ )) )
  {
   @tableauuri1 = ( $http_uri03, $http_uri14 ) if $http_uri03 && $http_uri14 && !$http_uri11 && !$http_uri17 && !$pcre_uri20;
   my $tableauuri1index=0;
   foreach( @tableauuri1 )
   {
    $tableauuri1[$tableauuri1index++] =~ s/\\(?!x)//g;
    if( $_ =~ /\\x|^\^|\$$/ ) { undef @tableauuri1 }
   }
  }
  else
  {
   $abc1= "(?:$http_uri03.*?$http_uri14|$http_uri14.*?$http_uri03)" if $http_uri03 && $http_uri14 && !$http_uri11 && !$http_uri17 && !$pcre_uri20;
  }

  if( $http_uri03 && $http_uri17 && !$http_uri11 && !$http_uri14 && !$pcre_uri20 && (( $http_uri03 !~ /\\x|^\^|\$$/ ) or ( $http_uri17 !~ /\\x|^\^|\$$/ )) )
  {
   @tableauuri1 = ( $http_uri03, $http_uri17 ) if $http_uri03 && $http_uri17 && !$http_uri11 && !$http_uri14 && !$pcre_uri20;
   my $tableauuri1index=0;
   foreach( @tableauuri1 )
   {
    $tableauuri1[$tableauuri1index++] =~ s/\\(?!x)//g;
    if( $_ =~ /\\x|^\^|\$$/ ) { undef @tableauuri1 }
   }
  }
  else
  {
   $abc1= "(?:$http_uri03.*?$http_uri17|$http_uri17.*?$http_uri03)" if $http_uri03 && $http_uri17 && !$http_uri11 && !$http_uri14 && !$pcre_uri20;
  }

  $abc1= "(?:$http_uri03.*?$pcre_uri20|$pcre_uri20.*?$http_uri03)" if $http_uri03 && $pcre_uri20 && !$http_uri11 && !$http_uri14 && !$http_uri17;

  # three uri
  if( $http_uri03 && $http_uri11 && $http_uri14 && !$http_uri17 && !$pcre_uri20 && (( $http_uri03 !~ /\\x|^\^|\$$/ ) or ( $http_uri11 !~ /\\x|^\^|\$$/ ) or ( $http_uri14 !~ /\\x|^\^|\$$/ )) )
  {
   @tableauuri1 = ( $http_uri03, $http_uri11, $http_uri14 ) if $http_uri03 && $http_uri11 && $http_uri14 && !$http_uri17 && !$pcre_uri20;
   my $tableauuri1index=0;
   foreach( @tableauuri1 )
   {
    $tableauuri1[$tableauuri1index++] =~ s/\\(?!x)//g;
    if( $_ =~ /\\x|^\^|\$$/ ) { undef @tableauuri1 }
   }
  }
  else
  {
   $abc1= "(?:$http_uri03.*$http_uri11.*$http_uri14|$http_uri03.*$http_uri14.*$http_uri11|$http_uri14.*$http_uri11.*$http_uri03|$http_uri11.*$http_uri14.*$http_uri03)" if $http_uri03 && $http_uri11 && $http_uri14 && !$http_uri17 && !$pcre_uri20;
  }

  if( $http_uri03 && $http_uri11 && $http_uri17 && !$http_uri14 && !$pcre_uri20 && (( $http_uri03 !~ /\\x|^\^|\$$/ ) or ( $http_uri11 !~ /\\x|^\^|\$$/ ) or ( $http_uri17 !~ /\\x|^\^|\$$/ )) )
  {
   @tableauuri1 = ( $http_uri03, $http_uri11, $http_uri17 ) if $http_uri03 && $http_uri11 && $http_uri17 && !$http_uri14 && !$pcre_uri20;
   my $tableauuri1index=0;
   foreach( @tableauuri1 )
   {
    $tableauuri1[$tableauuri1index++] =~ s/\\(?!x)//g;
    if( $_ =~ /\\x|^\^|\$$/ ) { undef @tableauuri1 }
   }
  }
  else
  {
   $abc1= "(?:$http_uri03.*$http_uri11.*$http_uri17|$http_uri03.*$http_uri17.*$http_uri11|$http_uri17.*$http_uri11.*$http_uri03|$http_uri11.*$http_uri17.*$http_uri03)" if $http_uri03 && $http_uri11 && $http_uri17 && !$http_uri14 && !$pcre_uri20;
  }

  $abc1= "(?:$http_uri03.*$http_uri11.*$pcre_uri20|$http_uri03.*$pcre_uri20.*$http_uri11|$pcre_uri20.*$http_uri11.*$http_uri03|$http_uri11.*$pcre_uri20.*$http_uri03)" if $http_uri03 && $http_uri11 && $pcre_uri20 && !$http_uri14 && !$http_uri17;

  # four uri
  $abc1= "(?:$http_uri03.*$http_uri11.*$http_uri14.*$pcre_uri20|$http_uri03.*$http_uri11.*$pcre_uri20.*$http_uri14|$http_uri03.*$http_uri14.*$http_uri11.*$pcre_uri20|$http_uri03.*$http_uri14.*$pcre_uri20.*$http_uri11|$http_uri11.*$http_uri14.*$pcre_uri20.*$http_uri03|$http_uri11.*$http_uri14.*$http_uri03.*$pcre_uri20|$http_uri11.*$http_uri03.*$http_uri14.*$pcre_uri20|$http_uri11.*$http_uri03.*$pcre_uri20.*$http_uri14|$http_uri14.*$http_uri03.*$http_uri11.*$pcre_uri20|$http_uri14.*$http_uri03.*$pcre_uri20.*$http_uri11|$http_uri14.*$http_uri11.*$pcre_uri20.*$http_uri03|$http_uri14.*$http_uri11.*$http_uri03.*$pcre_uri20|$pcre_uri20.*$http_uri03.*$http_uri11.*$http_uri14|$pcre_uri20.*$http_uri03.*$http_uri14.*$http_uri11|$pcre_uri20.*$http_uri14.*$http_uri03.*$http_uri11|$pcre_uri20.*$http_uri14.*$http_uri11.*$http_uri03)" if $http_uri03 && $http_uri11 && $http_uri14 && $pcre_uri20 && !$http_uri17;

  # uri:
  my $abc1_nocase=0;
     $abc1_nocase=$http_urifast5    if $http_urifast5;
     $abc1_nocase=$http_urinocase5  if $http_urinocase5;
     $abc1_nocase=$http_urifast19   if $http_urifast19;
     $abc1_nocase=$http_urinocase16 if $http_urinocase16;
     $abc1_nocase=$http_urifast24   if $http_urifast24;
     $abc1_nocase=$http_urinocase20 if $http_urinocase20;
     $abc1_nocase=$http_urifast29   if $http_urifast29;
     $abc1_nocase=$http_urinocase23 if $http_urinocase23;
  # header:
  my $httppcreagent_nocase=0;
     $httppcreagent_nocase=$http_headernocase9 if $http_headernocase9;
     $httppcreagent_nocase=$http_headernocase12 if $http_headernocase12;

  print "httpuricourt2: $etmsg1, $httpuricourt\n" if $debug1 && $httpuricourt;
  print "httpurilong2: $etmsg1, @tableauuri1\n" if $debug1 && @tableauuri1;
  print "tableaupcreuri2: $etmsg1, $abc1\n" if $debug1 && $abc1;
  print "tableaupcreagent2: $etmsg1, $httppcreagent\n" if $debug1 && $httppcreagent;
  print "httpagentshort2: $etmsg1, $httpagentshort\n" if $debug1 && $httpagentshort;
  print "tableauhttpmethod2: $etmsg1, $http_method2\n" if $debug1 && $http_method2;
  print "tableaupcrereferer2: $etmsg1, $pcrereferer\n" if $debug1 && $pcrereferer;

  $hash{$etmsg1}{httpuricourt} = [ $httpuricourt ] if $httpuricourt;
  $hash{$etmsg1}{httpagentshort} = [ $httpagentshort ] if $httpagentshort;
  $hash{$etmsg1}{httpmethod} = [ $http_method2, $http_methodnocase3 ] if $http_method2;
  $hash{$etmsg1}{pcrereferer} = [ $pcrereferer ] if $pcrereferer;
  $hash{$etmsg1}{pcreuri} = [ $abc1, $abc1_nocase ] if $abc1;
  $hash{$etmsg1}{pcreagent} = [ $httppcreagent, $httppcreagent_nocase ] if $httppcreagent;
  $hash{$etmsg1}{httpurilong} = [ @tableauuri1 ] if @tableauuri1;

  next;
 }

 # begin http_uri followed by a http_header
 elsif( $_=~ /^\s*alert\s+(?:udp|tcp)\s+\S+\s+\S+\s+\-\>\s+$category\s+\S+\s+\(\s*msg\:\s*\"([^\"]*?)\"\s*\;\s*(?:$flowbits1)?(?:$flow1)?(?:$httpmethod)?\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*\s*http_uri\;(?:$contentoptions1)*(?:$negateuricontent1)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*\s*http_header\;(?:$contentoptions1)*(?:$negateuricontent1)?)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*(?:\s*http_uri\;)?(?:$contentoptions1)*(?:$negateuricontent1)?)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*\s*http_header\;(?:$contentoptions1)*(?:$negateuricontent1)?)?(?:$pcreuri)?(?:$extracontentoptions)?$referencesidrev$/ )
 {
  my $etmsg1=$1;
  my $http_method2=0;
  my $http_methodnocase3=0;
  print "brut3: $_\n" if $debug1;
  #print "here3: 1: $1, 2: $2, 3: $3, 4: $4, 5: $5, 6: $6, 7: $7, 8: $8, 9: $9, 10: $10, 11: $11, 12: $12, 13: $13, 14: $14, 15: $15, 16: $16, 17: $17, 18: $18, 19: $19, 20: $20, 21: $21, 22: $22, 23: $23, 24: $24, 25: $25, 26: $26, 27: $27, 28: $28, 29: $29, 30: $30, 31: $31, 32: $32, 33: $33, 34: $34, 35: $35, 36: $36, 37: $37, $38, $39, 40: $40\n" if $debug1;

     $http_method2=$2 if $2;
     $http_methodnocase3=$3 if $3;
  my $http_uri03=$4 if $4;			# 3
  my $http_urifast5=$5 if $5;
  my $http_urinocase5=$6 if $6;			# 5
  my $http_urifast9=$9 if $9;
  my $http_urinocase8=$10 if $10;		# 8
  my $http_header08=$13 if $13;			# 11
  my $http_headerfast14=$14 if $14;
  my $http_headernocase12=$15 if $15;		# 12
  my $http_headerfast18=$18 if $18;
  my $http_headernocase15=$19 if $19;		# 15
  my $http_uri13=$22 if $22;			# 18
  my $http_urifast23=$23 if $23;
  my $http_urinocase19=$24 if $24;		# 19
  my $distance14=$25 if defined($25);		# 20
  my $distance15=$26 if defined($26);		# 21
  my $http_urifast27=$27 if $27;
  my $http_urinocase22=$28 if $28;		# 22
  my $distance16=$29 if defined($29);		# 23
  my $distance17=$30 if defined($30);		# 24
  my $http_header18=$31 if $31;			# 25
  my $http_headerfast32=$32 if $32;
  my $http_headernocase26=$33 if $33;		# 26
  my $distance34=$34 if defined($34);
  my $distance35=$35 if defined($35);
  my $http_headerfast36=$36 if $36;
  my $http_headernocase29=$37 if $37;		# 29
  my $distance38=$38 if defined($38);
  my $distance39=$39 if defined($39);
  my $pcre_uri23=$40 if $40;			# 32

  # check what is http_uri best length ?
  my $httpuricourt=0;
  my $http_uri03_length=0;
  my $http_uri13_length=0;
  $http_uri03_length=length($http_uri03) if $http_uri03;
  $http_uri13_length=length($http_uri13) if $http_uri13;
  if( $http_uri03_length >= $http_uri13_length )
  { $httpuricourt=$http_uri03; }
  elsif( $http_uri13_length >= $http_uri03_length )
  { $httpuricourt=$http_uri13; }

  $http_uri03 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri03; # (
  $http_uri03 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri03; # )
  $http_uri03 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri03; # *
  $http_uri03 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri03; # +
  $http_uri03 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri03; # -
  $http_uri03 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri03; # .
  $http_uri03 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri03; # /
  $http_uri03 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri03; # ?
  $http_uri03 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri03; # [
  $http_uri03 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri03; # ]
  $http_uri03 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri03; # ^
  $http_uri03 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri03; # {
  $http_uri03 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri03; # }
  $http_header08 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_header08; # (
  $http_header08 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_header08; # )
  $http_header08 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_header08; # *
  $http_header08 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_header08; # +
  $http_header08 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_header08; # -
  $http_header08 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_header08; # .
  $http_header08 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_header08; # /
  $http_header08 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_header08; # ?
  $http_header08 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_header08; # [
  $http_header08 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_header08; # ]
  #$http_header08 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_header08; # ^
  $http_header08 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_header08; # {
  $http_header08 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_header08; # }
  $http_uri13 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri13; # (
  $http_uri13 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri13; # )
  $http_uri13 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri13; # *
  $http_uri13 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri13; # +
  $http_uri13 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri13; # -
  $http_uri13 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri13; # .
  $http_uri13 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri13; # /
  $http_uri13 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri13; # ?
  $http_uri13 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri13; # [
  $http_uri13 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri13; # ]
  $http_uri13 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri13; # ^
  $http_uri13 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri13; # {
  $http_uri13 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri13; # }
  $http_header18 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_header18; # (
  $http_header18 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_header18; # )
  $http_header18 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_header18; # *
  $http_header18 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_header18; # +
  $http_header18 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_header18; # -
  $http_header18 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_header18; # .
  $http_header18 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_header18; # /
  $http_header18 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_header18; # ?
  $http_header18 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_header18; # [
  $http_header18 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_header18; # ]
  #$http_header18 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_header18; # ^
  $http_header18 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_header18; # {
  $http_header18 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_header18; # }
  #$pcre_uri23 =~ s/(?<!\x5C)\x24//g         if $pcre_uri23; # $

#perl -e '$abc1="1|20 21|2|22 24|3";while($abc1=~/(?<!\x5C)\|(.*?)\|/g){$toto1=$1;print "abc1:$abc1\ntoto1:$toto1\n";$toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g; print "$toto1\n"; $abc1=~s/(?<!\x5C)\|.*?\|/$toto1/}; print "final:$abc1\n"'
  while($http_uri03 && $http_uri03=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_uri03=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  while($http_header08 && $http_header08=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_header08=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  while($http_uri13 && $http_uri13=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_uri13=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
   while($http_header18 && $http_header18=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_header18=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  # ne pas faire d'echappement sur la pcre ($pcre_uri23)
  my $abc1=0;
  my $httppcreagent=0;
  my $httpagentshort=0;
  my $pcrereferer=0;
  my @tableauuri1;

     if( $http_header08 && $http_header08 =~ s/\QUser\-Agent\x3A\x20\E(?!$)/^/i ) { }
  elsif( $http_header08 && $http_header08 =~ s/\QUser\-Agent\x3A\x20\E$/^/i ) { undef($http_header08) }
  elsif( $http_header08 && $http_header08 =~ s/\QUser\-Agent\x3A \E(?!$)/^/i ) { }
  elsif( $http_header08 && $http_header08 =~  /\QUser\-Agent\x3A \E$/i ) { undef($http_header08) }
  elsif( $http_header08 && $http_header08 =~ s/\QUser-Agent\x3A \E(?!$)/^/i ) { }
  elsif( $http_header08 && $http_header08 =~  /\QUser-Agent\x3A \E$/i ) { undef($http_header08) }
  elsif( $http_header08 && $http_header08 =~ s/\QUser\-Agent\: \E(?!$)/^/i ) { }
  elsif( $http_header08 && $http_header08 =~  /\QUser\-Agent\: \E$/i ) { undef($http_header08) }
  elsif( $http_header08 && $http_header08 =~ s/\QUser-Agent\: \E(?!$)/^/i ) { }
  elsif( $http_header08 && $http_header08 =~  /\QUser-Agent\: \E$/i ) { undef($http_header08) }
  elsif( $http_header08 && $http_header08 =~ s/\QUser\-Agent\x3A\E(?!$)/^/i ) { }
  elsif( $http_header08 && $http_header08 =~  /\QUser\-Agent\x3A\E$/i ) { undef($http_header08) }
  elsif( $http_header08 && $http_header08 =~ s/\QUser-Agent\x3A\E(?!$)/^/i ) { }
  elsif( $http_header08 && $http_header08 =~  /\QUser-Agent\x3A\E$/i ) { undef($http_header08) }
  elsif( $http_header08 && $http_header08 =~ s/\QUser\-Agent\:\E(?!$)/^/i ) { }
  elsif( $http_header08 && $http_header08 =~  /\QUser\-Agent\:\E$/i ) { undef($http_header08) }
  elsif( $http_header08 && $http_header08 =~ s/\QUser-Agent\:\E(?!$)/^/i ) { }
  elsif( $http_header08 && $http_header08 =~  /\QUser-Agent\:\E$/i ) { undef($http_header08) }
                           $http_header08 =~ s/\Q\x0D\x0A\E/\$/i if $http_header08; # http_header, \x0D\x0A
     if( $http_header18 && $http_header18 =~ s/\QUser\-Agent\x3A\x20\E(?!$)/^/i ) { }
  elsif( $http_header18 && $http_header18 =~ s/\QUser\-Agent\x3A\x20\E$/^/i ) { undef($http_header18) }
  elsif( $http_header18 && $http_header18 =~ s/\QUser\-Agent\x3A \E(?!$)/^/i ) { }
  elsif( $http_header18 && $http_header18 =~  /\QUser\-Agent\x3A \E$/i ) { undef($http_header18) }
  elsif( $http_header18 && $http_header18 =~ s/\QUser-Agent\x3A \E(?!$)/^/i ) { }
  elsif( $http_header18 && $http_header18 =~  /\QUser-Agent\x3A \E$/i ) { undef($http_header18) }
  elsif( $http_header18 && $http_header18 =~ s/\QUser\-Agent\: \E(?!$)/^/i ) { }
  elsif( $http_header18 && $http_header18 =~  /\QUser\-Agent\: \E$/i ) { undef($http_header18) }
  elsif( $http_header18 && $http_header18 =~ s/\QUser-Agent\: \E(?!$)/^/i ) { }
  elsif( $http_header18 && $http_header18 =~  /\QUser-Agent\: \E$/i ) { undef($http_header18) }
  elsif( $http_header18 && $http_header18 =~ s/\QUser\-Agent\x3A\E(?!$)/^/i ) { }
  elsif( $http_header18 && $http_header18 =~  /\QUser\-Agent\x3A\E$/i ) { undef($http_header18) }
  elsif( $http_header18 && $http_header18 =~ s/\QUser-Agent\x3A\E(?!$)/^/i ) { }
  elsif( $http_header18 && $http_header18 =~  /\QUser-Agent\x3A\E$/i ) { undef($http_header18) }
  elsif( $http_header18 && $http_header18 =~ s/\QUser\-Agent\:\E(?!$)/^/i ) { }
  elsif( $http_header18 && $http_header18 =~  /\QUser\-Agent\:\E$/i ) { undef($http_header18) }
  elsif( $http_header18 && $http_header18 =~ s/\QUser-Agent\:\E(?!$)/^/i ) { }
  elsif( $http_header18 && $http_header18 =~  /\QUser-Agent\:\E$/i ) { undef($http_header18) }
                           $http_header18 =~ s/\Q\x0D\x0A\E/\$/i if $http_header18; # http_header, \x0D\x0A
     if( $http_header08 && $http_header08 =~ s/\QReferer\x3A\x20\E/^/i ) { $pcrereferer = $http_header08; undef $http_header08 }
  elsif( $http_header08 && $http_header08 =~ s/\QReferer\x3A \E/^/i ) { $pcrereferer = $http_header08; undef $http_header08 }
     if( $http_header18 && $http_header18 =~ s/\QReferer\x3A\x20\E/^/i ) { $pcrereferer = $http_header18; undef $http_header18 }
  elsif( $http_header18 && $http_header18 =~ s/\QReferer\x3A \E/^/i ) { $pcrereferer = $http_header18; undef $http_header18 }

  if( $pcre_uri23 )
  {
   $pcre_uri23 =~ s/^\^\\\//\^(?:https?\\\:\\\/\\\/)?[^\\\/]*?\\\//i;
   $pcre_uri23 =~ s/^\^\\x2F/\^(?:https?\\\:\\\/\\\/)?[^\\\/]*?\\x2F/i;
  }

  # http_user_agent short
  if( $http_header08 && $http_header18 && length($http_header08) >= length($http_header18) )
  {
   $httpagentshort= "$http_header08" if $http_header08;
  }
  elsif( $http_header08 && $http_header18 && length($http_header18) >= length($http_header08) )
  {
   $httpagentshort= "$http_header18" if $http_header18;
  }
  elsif( $http_header08 )
  {
   $httpagentshort= "$http_header08" if $http_header08;
  }
  elsif( $http_header18 )
  {
   $httpagentshort= "$http_header18" if $http_header18;
  }
  while( $httpagentshort =~ /\\x(..)/g )
  {
   my $tempochr=chr(hex("$1"));
   $httpagentshort =~ s/\\x(..)/$tempochr/;
  }
  $httpagentshort =~ s/(?:\\|\^|\$)//g;

  if( $pcre_uri23 && $http_uri03 && $pcre_uri23=~/\Q$http_uri03\E/i ) {
   undef $http_uri03;
   print "ok trouver grep3a\n" if $debug1;
  }
  elsif( $pcre_uri23 && $http_uri03 && $http_uri03=~s/\&/\\x26/g && $pcre_uri23=~/\Q$http_uri03\E/i ) {
   undef $http_uri03; 
   print "ok trouver grep3b\n" if $debug1;
  }
  elsif( $pcre_uri23 && $http_uri03 && $http_uri03=~s/\=/\\x3D/g && $pcre_uri23=~/\Q$http_uri03\E/i ) {
   undef $http_uri03; 
   print "ok trouver grep3c\n" if $debug1;
  }
  if( $pcre_uri23 && $http_header08 && $pcre_uri23=~/\Q$http_header08\E/i ) {
   undef $http_header08; 
   print "ok trouver grep8a\n" if $debug1;
  }
  elsif( $pcre_uri23 && $http_header08 && $http_header08=~s/\&/\\x26/g && $pcre_uri23=~/\Q$http_header08\E/i ) {
   undef $http_header08;
   print "ok trouver grep8b\n" if $debug1;
  }
  elsif( $pcre_uri23 && $http_header08 && $http_header08=~s/\=/\\x3D/g && $pcre_uri23=~/\Q$http_header08\E/i ) {
   undef $http_header08;
   print "ok trouver grep8c\n" if $debug1;
  }
  if( $pcre_uri23 && $http_uri13 && $pcre_uri23=~/\Q$http_uri13\E/i ) {
   undef $http_uri13;
   print "ok trouver grep13a\n" if $debug1;
  }
  elsif( $pcre_uri23 && $http_uri13 && $http_uri13=~s/\&/\\x26/g && $pcre_uri23=~/\Q$http_uri13\E/i ) {
   undef $http_uri13;
   print "ok trouver grep13b\n" if $debug1;
  }
  elsif( $pcre_uri23 && $http_uri13 && $http_uri13=~s/\=/\\x3D/g && $pcre_uri23=~/\Q$http_uri13\E/i ) {
   undef $http_uri13;
   print "ok trouver grep13c\n" if $debug1;
  }
  if( $pcre_uri23 && $http_header18 && $pcre_uri23=~/\Q$http_header18\E/i ) {
   undef $http_header18;
   print "ok trouver grep18a\n" if $debug1;
  }
  elsif( $pcre_uri23 && $http_header18 && $http_header18=~s/\&/\\x26/g && $pcre_uri23=~/\Q$http_header18\E/i ) {
   undef $http_header18;
   print "ok trouver grep18b\n" if $debug1;
  }
  elsif( $pcre_uri23 && $http_header18 && $http_header18=~s/\=/\\x3D/g && $pcre_uri23=~/\Q$http_header18\E/i ) {
   undef $http_header18;
   print "ok trouver grep18c\n" if $debug1;
  }

  # one uri
  #$abc1= "$http_uri03" if $http_uri03 && !$http_uri13 && !$pcre_uri23;
  #$abc1= "$http_uri13" if $http_uri13 && !$http_uri03 && !$pcre_uri23;
  $abc1= "$pcre_uri23" if $pcre_uri23 && !$http_uri03 && !$http_uri13;

  # one header
  #$httppcreagent= "$http_header08" if $http_header08 && !$http_header18;
  #$httppcreagent= "$http_header18" if $http_header18 && !$http_header08;

  # two header
  $httppcreagent= "(?:$http_header08.*?$http_header18|$http_header18.*?$http_header08)" if $http_header08 && $http_header18;

  # two uri
  if( $http_uri03 && $http_uri13 && (( $http_uri03 !~ /\\x|^\^|\$$/ ) or ( $http_uri13 !~ /\\x|^\^|\$$/ )) )
  {
   @tableauuri1 = ( $http_uri03, $http_uri13 ) if $http_uri03 && $http_uri13 && !$pcre_uri23;
   my $tableauuri1index=0;
   foreach( @tableauuri1 )
   {
    $tableauuri1[$tableauuri1index++] =~ s/\\(?!x)//g;
    if( $_ =~ /\\x|^\^|\$$/ ) { undef @tableauuri1 }
   }
  }
  else
  {
   $abc1= "(?:$http_uri03.*?$http_uri13|$http_uri13.*?$http_uri03)" if $http_uri03 && $http_uri13 && !$pcre_uri23;
  }

  $abc1= "(?:$http_uri03.*?$pcre_uri23|$pcre_uri23.*?$http_uri03)" if $http_uri03 && $pcre_uri23 && !$http_uri13;

  # three uri
  $abc1= "(?:$http_uri03.*$http_uri13.*$pcre_uri23|$http_uri03.*$pcre_uri23.*$http_uri13|$pcre_uri23.*$http_uri13.*$http_uri03|$http_uri13.*$pcre_uri23.*$http_uri03)" if $http_uri03 && $http_uri13 && $pcre_uri23;

  # uri:
  my $abc1_nocase=0;
     $abc1_nocase=$http_urifast5    if $http_urifast5;
     $abc1_nocase=$http_urinocase5  if $http_urinocase5;
     $abc1_nocase=$http_urifast9    if $http_urifast9;
     $abc1_nocase=$http_urinocase8  if $http_urinocase8;
     $abc1_nocase=$http_urifast23   if $http_urifast23;
     $abc1_nocase=$http_urinocase19 if $http_urinocase19;
     $abc1_nocase=$http_urifast27   if $http_urifast27;
     $abc1_nocase=$http_urinocase22 if $http_urinocase22;
  # header:
  my $httppcreagent_nocase=0;
     $httppcreagent_nocase=$http_headerfast14   if $http_headerfast14;
     $httppcreagent_nocase=$http_headernocase12 if $http_headernocase12;
     $httppcreagent_nocase=$http_headerfast18   if $http_headerfast18;
     $httppcreagent_nocase=$http_headernocase15 if $http_headernocase15;
     $httppcreagent_nocase=$http_headerfast32   if $http_headerfast32;
     $httppcreagent_nocase=$http_headernocase26 if $http_headernocase26;
     $httppcreagent_nocase=$http_headerfast36   if $http_headerfast36;
     $httppcreagent_nocase=$http_headernocase29 if $http_headernocase29;

  print "httpuricourt3: $etmsg1, $httpuricourt\n" if $debug1 && $httpuricourt;
  print "httpurilong3: $etmsg1, @tableauuri1\n" if $debug1 && @tableauuri1;
  print "tableaupcreuri3: $etmsg1, $abc1\n" if $debug1 && $abc1;
  print "tableaupcreagent3: $etmsg1, $httppcreagent\n" if $debug1 && $httppcreagent;
  print "httpagentshort3: $etmsg1, $httpagentshort\n" if $debug1 && $httpagentshort;
  print "tableauhttpmethod3: $etmsg1, $http_method2\n" if $debug1 && $http_method2;
  print "tableaupcrereferer3: $etmsg1, $pcrereferer\n" if $debug1 && $pcrereferer;

  $hash{$etmsg1}{httpuricourt} = [ $httpuricourt ] if $httpuricourt;
  $hash{$etmsg1}{httpagentshort} = [ $httpagentshort ] if $httpagentshort;
  $hash{$etmsg1}{httpmethod} = [ $http_method2, $http_methodnocase3 ] if $http_method2;
  $hash{$etmsg1}{pcrereferer} = [ $pcrereferer ] if $pcrereferer;
  $hash{$etmsg1}{pcreuri} = [ $abc1, $abc1_nocase ] if $abc1;
  $hash{$etmsg1}{pcreagent} = [ $httppcreagent, $httppcreagent_nocase ] if $httppcreagent;
  $hash{$etmsg1}{httpurilong} = [ @tableauuri1 ] if @tableauuri1;

  next;
 }

 # begin http_header
 elsif( $_=~ /^\s*alert\s+(?:udp|tcp)\s+\S+\s+\S+\s+\-\>\s+$category\s+\S+\s+\(\s*msg\:\s*\"([^\"]*?)\"\s*\;\s*(?:$flow1)?(?:$urilen1)?(?:$httpmethod)?(?:$negateuricontent1)?\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*\s*http_header\;(?:$contentoptions1)*(?:$negateuricontent1)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*\s*http_uri\;(?:$contentoptions1)*(?:$negateuricontent1)?)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*\s*http_header\;(?:$contentoptions1)*(?:$negateuricontent1)?)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*\s*http_uri\;(?:$contentoptions1)*(?:$negateuricontent1)?)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*\s*http_header\;(?:$contentoptions1)*(?:$negateuricontent1)?)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)*\s*http_uri\;(?:$contentoptions1)*(?:$negateuricontent1)?)?(?:$pcreuri)?(?:$pcreagent)?(?:$extracontentoptions)?$referencesidrev$/ )
 {
  my $etmsg1=$1;
  my $http_method2=0;
  my $http_methodnocase3=0;
  print "brut4: $_\n" if $debug1;
  #print "here4: 1: $1, 2: $2, 3: $3, 4: $4, 5: $5, 6: $6, 7: $7, 8: $8, 9: $9, 10: $10, 11: $11, 12: $12, 13: $13, 14: $14, 15: $15, 16: $16, 17: $17, 18: $18, 19: $19, 20: $20, 21: $21, 22: $22, 23: $23, 24: $24, 25: $25, 26: $26, 27: $27, 28: $28, 29: $29, 30: $30, 31: $31, 32: $32, 33: $33, 34: $34, 35: $35, 36: $36, 37: $37, $38, $39, 40: $40, $41, $42, $43, $44, $45, $46, $47, $48, $49, 50: $50, $51, $52, $53, 54: $54, $55, $56, $57, $58, 59: $59\n" if $debug1;

     $http_method2=$2 if $2;
     $http_methodnocase3=$3 if $3;
  my $http_header03=$4 if $4;		# 4
  my $http_headerfast5=$5 if $5;
  my $http_headernocase5=$6 if $6;	# 5
  my $http_headerfast9=$9 if $9;
  my $http_headernocase8=$10 if $10;	# 8
  my $http_uri08=$13 if $13;		# 11
  my $http_urifast14=$14 if $14;
  my $http_urinocase12=$15 if $15;	# 12
  my $http_urifast18=$18 if $18;
  my $http_urinocase15=$19 if $19;	# 15
  my $http_header13=$22 if $22;		# 18
  my $http_headerfast23=$23 if $23;
  my $http_headernocase19=$24 if $24;	# 19
  my $distance14=$25 if defined($25);	# 20
  my $distance15=$26 if defined($26);	# 21
  my $http_headerfast27=$27 if $27;
  my $http_headernocase22=$28 if $28;	# 22
  my $distance16=$29 if defined($29);	# 23
  my $distance17=$30 if defined($30);	# 24
  my $http_uri18=$31 if $31;		# 25
  my $http_urifast32=$32 if $32;
  my $http_urinocase25=$33 if $33;	# 26
  my $distance19=$34 if defined($34);	# 27
  my $distance20=$35 if defined($35);	# 28
  my $http_urifast36=$36 if $36;
  my $http_urinocase28=$37 if $37;	# 29
  my $distance21=$38 if defined($38);	# 30
  my $distance22=$39 if defined($39);	# 31
  my $http_header23=$40 if $40;		# 32
  my $http_headerfast41=$41 if $41;
  my $http_headernocase32=$42 if $42;	# 33
  my $distance24=$43 if defined($43);	# 34
  my $distance25=$44 if defined($44);	# 35
  my $http_headerfast45=$45 if $45;
  my $http_headernocase35=$46 if $46;	# 36
  my $distance26=$47 if defined($47);	# 37
  my $distance27=$48 if defined($48);	# 38
  my $http_uri28=$49 if $49;		# 39
  my $http_urifast50=$50 if $50;
  my $http_urinocase39=$51 if $51;	# 40
  my $distance29=$52 if defined($52);	# 41
  my $distance30=$53 if defined($53);	# 42
  my $http_urifast54=$54 if $54;
  my $http_urinocase42=$55 if $55;	# 43
  my $distance31=$56 if defined($56);	# 44
  my $distance32=$57 if defined($57);	# 45
  my $pcre_uri33=$58 if $58;		# 46
  my $pcre_agent34=$59 if $59;		# 47

  # check what is http_uri best length ?
  my $httpuricourt=0;
  my $http_uri08_length=0;
  my $http_uri18_length=0;
  my $http_uri28_length=0;
  $http_uri08_length=length($http_uri08) if $http_uri08;
  $http_uri18_length=length($http_uri18) if $http_uri18;
  $http_uri28_length=length($http_uri28) if $http_uri28;
  if( $http_uri08_length >= $http_uri18_length && $http_uri08_length >= $http_uri28_length )
  { $httpuricourt=$http_uri08; }
  elsif( $http_uri18_length >= $http_uri08_length && $http_uri18_length >= $http_uri28_length )
  { $httpuricourt=$http_uri18; }
  elsif( $http_uri28_length >= $http_uri08_length && $http_uri28_length >= $http_uri18_length )
  { $httpuricourt=$http_uri28; }

  $http_header03 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_header03; # (
  $http_header03 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_header03; # )
  $http_header03 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_header03; # *
  $http_header03 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_header03; # +
  $http_header03 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_header03; # -
  $http_header03 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_header03; # .
  $http_header03 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_header03; # /
  $http_header03 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_header03; # ?
  $http_header03 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_header03; # [
  $http_header03 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_header03; # ]
  #$http_header03 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_header03; # ^
  $http_header03 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_header03; # {
  $http_header03 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_header03; # }
  $http_uri08 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri08; # (
  $http_uri08 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri08; # )
  $http_uri08 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri08; # *
  $http_uri08 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri08; # +
  $http_uri08 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri08; # -
  $http_uri08 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri08; # .
  $http_uri08 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri08; # /
  $http_uri08 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri08; # ?
  $http_uri08 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri08; # [
  $http_uri08 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri08; # ]
  $http_uri08 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri08; # ^
  $http_uri08 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri08; # {
  $http_uri08 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri08; # }
  $http_header13 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_header13; # (
  $http_header13 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_header13; # )
  $http_header13 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_header13; # *
  $http_header13 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_header13; # +
  $http_header13 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_header13; # -
  $http_header13 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_header13; # .
  $http_header13 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_header13; # /
  $http_header13 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_header13; # ?
  $http_header13 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_header13; # [
  $http_header13 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_header13; # ]
  #$http_header13 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_header13; # ^
  $http_header13 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_header13; # {
  $http_header13 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_header13; # }
  $http_uri18 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri18; # (
  $http_uri18 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri18; # )
  $http_uri18 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri18; # *
  $http_uri18 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri18; # +
  $http_uri18 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri18; # -
  $http_uri18 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri18; # .
  $http_uri18 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri18; # /
  $http_uri18 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri18; # ?
  $http_uri18 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri18; # [
  $http_uri18 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri18; # ]
  $http_uri18 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri18; # ^
  $http_uri18 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri18; # {
  $http_uri18 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri18; # }
  $http_header23 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_header23; # (
  $http_header23 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_header23; # )
  $http_header23 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_header23; # *
  $http_header23 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_header23; # +
  $http_header23 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_header23; # -
  $http_header23 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_header23; # .
  $http_header23 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_header23; # /
  $http_header23 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_header23; # ?
  $http_header23 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_header23; # [
  $http_header23 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_header23; # ]
  #$http_header23 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_header23; # ^
  $http_header23 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_header23; # {
  $http_header23 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_header23; # }
  $http_uri28 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri28; # (
  $http_uri28 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri28; # )
  $http_uri28 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri28; # *
  $http_uri28 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri28; # +
  $http_uri28 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri28; # -
  $http_uri28 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri28; # .
  $http_uri28 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri28; # /
  $http_uri28 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri28; # ?
  $http_uri28 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri28; # [
  $http_uri28 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri28; # ]
  $http_uri28 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri28; # ^
  $http_uri28 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri28; # {
  $http_uri28 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri28; # }
  #$pcre_uri33 =~ s/(?<!\x5C)\x24//g         if $pcre_uri33; # $
  #$pcre_agent34 =~ s/(?<!\x5C)\x24//g         if $pcre_agent34; # $

#perl -e '$abc1="1|20 21|2|22 24|3";while($abc1=~/(?<!\x5C)\|(.*?)\|/g){$toto1=$1;print "abc1:$abc1\ntoto1:$toto1\n";$toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g; print "$toto1\n"; $abc1=~s/(?<!\x5C)\|.*?\|/$toto1/}; print "final:$abc1\n"'
  while($http_header03 && $http_header03=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_header03=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  while($http_uri08 && $http_uri08=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_uri08=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  while($http_header13 && $http_header13=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_header13=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
   while($http_uri18 && $http_uri18=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_uri18=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
   while($http_header23 && $http_header23=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_header23=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
   while($http_uri28 && $http_uri28=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_uri28=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  # ne pas faire d'echappement sur la pcre ($pcre_uri33 et $pcre_agent34)
  my $abc1=0;
  my $httppcreagent=0;
  my $httpagentshort=0;
  my $pcrereferer=0;
  my $cookie=0;
  my @tableauuri1;

     if( $http_header03 && $http_header03 =~ s/\QUser\-Agent\x3A\x20\E(?!$)/^/i ) { }
  elsif( $http_header03 && $http_header03 =~ s/\QUser\-Agent\x3A\x20\E$/^/i ) { undef($http_header03) }
  elsif( $http_header03 && $http_header03 =~ s/\QUser\-Agent\x3A \E(?!$)/^/i ) { }
  elsif( $http_header03 && $http_header03 =~  /\QUser\-Agent\x3A \E$/i ) { undef($http_header03) }
  elsif( $http_header03 && $http_header03 =~ s/\QUser-Agent\x3A \E(?!$)/^/i ) { }
  elsif( $http_header03 && $http_header03 =~  /\QUser-Agent\x3A \E$/i ) { undef($http_header03) }
  elsif( $http_header03 && $http_header03 =~ s/\QUser\-Agent\: \E(?!$)/^/i ) { }
  elsif( $http_header03 && $http_header03 =~  /\QUser\-Agent\: \E$/i ) { undef($http_header03) }
  elsif( $http_header03 && $http_header03 =~ s/\QUser-Agent\: \E(?!$)/^/i ) { }
  elsif( $http_header03 && $http_header03 =~  /\QUser-Agent\: \E$/i ) { undef($http_header03) }
  elsif( $http_header03 && $http_header03 =~ s/\QUser\-Agent\x3A\E(?!$)/^/i ) { }
  elsif( $http_header03 && $http_header03 =~  /\QUser\-Agent\x3A\E$/i ) { undef($http_header03) }
  elsif( $http_header03 && $http_header03 =~ s/\QUser-Agent\x3A\E(?!$)/^/i ) { }
  elsif( $http_header03 && $http_header03 =~  /\QUser-Agent\x3A\E$/i ) { undef($http_header03) }
  elsif( $http_header03 && $http_header03 =~ s/\QUser\-Agent\:\E(?!$)/^/i ) { }
  elsif( $http_header03 && $http_header03 =~  /\QUser\-Agent\:\E$/i ) { undef($http_header03) }
  elsif( $http_header03 && $http_header03 =~ s/\QUser-Agent\:\E(?!$)/^/i ) { }
  elsif( $http_header03 && $http_header03 =~  /\QUser-Agent\:\E$/i ) { undef($http_header03) }
  #$http_header03 =~ s/\Q\x0D\x0A\E/\$/i if $http_header03; # http_header, \x0D\x0A
     if( $http_header13 && $http_header13 =~ s/\QUser\-Agent\x3A\x20\E(?!$)/^/i ) { }
  elsif( $http_header13 && $http_header13 =~ s/\QUser\-Agent\x3A\x20\E$/^/i ) { undef($http_header13) }
  elsif( $http_header13 && $http_header13 =~ s/\QUser\-Agent\x3A \E(?!$)/^/i ) { }
  elsif( $http_header13 && $http_header13 =~  /\QUser\-Agent\x3A \E$/i ) { undef($http_header13) }
  elsif( $http_header13 && $http_header13 =~ s/\QUser-Agent\x3A \E(?!$)/^/i ) { }
  elsif( $http_header13 && $http_header13 =~  /\QUser-Agent\x3A \E$/i ) { undef($http_header13) }
  elsif( $http_header13 && $http_header13 =~ s/\QUser\-Agent\: \E(?!$)/^/i ) { }
  elsif( $http_header13 && $http_header13 =~  /\QUser\-Agent\: \E$/i ) { undef($http_header13) }
  elsif( $http_header13 && $http_header13 =~ s/\QUser-Agent\: \E(?!$)/^/i ) { }
  elsif( $http_header13 && $http_header13 =~  /\QUser-Agent\: \E$/i ) { undef($http_header13) }
  elsif( $http_header13 && $http_header13 =~ s/\QUser\-Agent\x3A\E(?!$)/^/i ) { }
  elsif( $http_header13 && $http_header13 =~  /\QUser\-Agent\x3A\E$/i ) { undef($http_header13) }
  elsif( $http_header13 && $http_header13 =~ s/\QUser-Agent\x3A\E(?!$)/^/i ) { }
  elsif( $http_header13 && $http_header13 =~  /\QUser-Agent\x3A\E$/i ) { undef($http_header13) }
  elsif( $http_header13 && $http_header13 =~ s/\QUser\-Agent\:\E(?!$)/^/i ) { }
  elsif( $http_header13 && $http_header13 =~  /\QUser\-Agent\:\E$/i ) { undef($http_header13) }
  elsif( $http_header13 && $http_header13 =~ s/\QUser-Agent\:\E(?!$)/^/i ) { }
  elsif( $http_header13 && $http_header13 =~  /\QUser-Agent\:\E$/i ) { undef($http_header13) }
  #$http_header13 =~ s/\Q\x0D\x0A\E/\$/i if $http_header13; # http_header, \x0D\x0A
     if( $http_header23 && $http_header23 =~ s/\QUser\-Agent\x3A\x20\E(?!$)/^/i ) { }
  elsif( $http_header23 && $http_header23 =~ s/\QUser\-Agent\x3A\x20\E$/^/i ) { undef($http_header23) }
  elsif( $http_header23 && $http_header23 =~ s/\QUser\-Agent\x3A \E(?!$)/^/i ) { }
  elsif( $http_header23 && $http_header23 =~  /\QUser\-Agent\x3A \E$/i ) { undef($http_header23) }
  elsif( $http_header23 && $http_header23 =~ s/\QUser-Agent\x3A \E(?!$)/^/i ) { }
  elsif( $http_header23 && $http_header23 =~  /\QUser-Agent\x3A \E$/i ) { undef($http_header23) }
  elsif( $http_header23 && $http_header23 =~ s/\QUser\-Agent\: \E(?!$)/^/i ) { }
  elsif( $http_header23 && $http_header23 =~  /\QUser\-Agent\: \E$/i ) { undef($http_header23) }
  elsif( $http_header23 && $http_header23 =~ s/\QUser-Agent\: \E(?!$)/^/i ) { }
  elsif( $http_header23 && $http_header23 =~  /\QUser-Agent\: \E$/i ) { undef($http_header23) }
  elsif( $http_header23 && $http_header23 =~ s/\QUser\-Agent\x3A\E(?!$)/^/i ) { }
  elsif( $http_header23 && $http_header23 =~  /\QUser\-Agent\x3A\E$/i ) { undef($http_header23) }
  elsif( $http_header23 && $http_header23 =~ s/\QUser-Agent\x3A\E(?!$)/^/i ) { }
  elsif( $http_header23 && $http_header23 =~  /\QUser-Agent\x3A\E$/i ) { undef($http_header23) }
  elsif( $http_header23 && $http_header23 =~ s/\QUser\-Agent\:\E(?!$)/^/i ) { }
  elsif( $http_header23 && $http_header23 =~  /\QUser\-Agent\:\E$/i ) { undef($http_header23) }
  elsif( $http_header23 && $http_header23 =~ s/\QUser-Agent\:\E(?!$)/^/i ) { }
  elsif( $http_header23 && $http_header23 =~  /\QUser-Agent\:\E$/i ) { undef($http_header23) }
  #$http_header23 =~ s/\Q\x0D\x0A\E/\$/i if $http_header23; # http_header, \x0D\x0A
  $pcre_agent34 =~ s/\Q^User\-Agent\x3A\x20\E/^/i if $pcre_agent34;
  $pcre_agent34 =~ s/\Q^User\-Agent\x3A \E/^/i if $pcre_agent34;
  $pcre_agent34 =~ s/\QUser\-Agent\x3A\x20\E/^/i if $pcre_agent34;
  $pcre_agent34 =~ s/\QUser\-Agent\x3A \E/^/i if $pcre_agent34;
  $pcre_agent34 =~ s/\Q^User-Agent\x3A\x20\E/^/i if $pcre_agent34;
  $pcre_agent34 =~ s/\Q^User-Agent\x3A \E/^/i if $pcre_agent34;
  $pcre_agent34 =~ s/\QUser-Agent\x3A\x20\E/^/i if $pcre_agent34;
  $pcre_agent34 =~ s/\QUser-Agent\x3A \E/^/i if $pcre_agent34;
  $pcre_agent34 =~ s/\Q^User\-Agent\:\x20\E/^/i if $pcre_agent34;
  $pcre_agent34 =~ s/\Q^User\-Agent\: \E/^/i if $pcre_agent34;
  $pcre_agent34 =~ s/\QUser\-Agent\:\x20\E/^/i if $pcre_agent34;
  $pcre_agent34 =~ s/\QUser\-Agent\: \E/^/i if $pcre_agent34;
  $pcre_agent34 =~ s/\Q^User-Agent\:\x20\E/^/i if $pcre_agent34;
  $pcre_agent34 =~ s/\Q^User-Agent\: \E/^/i if $pcre_agent34;
  $pcre_agent34 =~ s/\QUser-Agent\:\x20\E/^/i if $pcre_agent34;
  $pcre_agent34 =~ s/\QUser-Agent\: \E/^/i if $pcre_agent34;
  $pcre_agent34 =~ s/\Q^User\-Agent\x3A\E/^/i if $pcre_agent34;
  $pcre_agent34 =~ s/\QUser\-Agent\x3A\E/^/i if $pcre_agent34;
  $pcre_agent34 =~ s/\Q^User-Agent\x3A\E/^/i if $pcre_agent34;
  $pcre_agent34 =~ s/\QUser-Agent\x3A\E/^/i if $pcre_agent34;
  $pcre_agent34 =~ s/\Q^User\-Agent\:\E/^/i if $pcre_agent34;
  $pcre_agent34 =~ s/\QUser\-Agent\:\E/^/i if $pcre_agent34;
  $pcre_agent34 =~ s/\Q^User-Agent\:\E/^/i if $pcre_agent34;
  $pcre_agent34 =~ s/\QUser-Agent\:\E/^/i if $pcre_agent34;
  #$pcre_agent34 =~ s/\Q\x0D\x0A\E/\$/i if $pcre_agent34; # http_header, \x0D\x0A
     if( $http_header03 && $http_header03 =~ s/\Q^Referer\x3A\x20\E/^/i ) { $http_header03 =~ s/\Q\x0D\x0A\E/\$/i; $pcrereferer = $http_header03; undef $http_header03 }
  elsif( $http_header03 && $http_header03 =~ s/\Q^Referer\x3A \E/^/i ) { $http_header03 =~ s/\Q\x0D\x0A\E/\$/i; $pcrereferer = $http_header03; undef $http_header03 }
  elsif( $http_header03 && $http_header03 =~ s/\QReferer\x3A\x20\E/^/i ) { $http_header03 =~ s/\Q\x0D\x0A\E/\$/i; $pcrereferer = $http_header03; undef $http_header03 }
  elsif( $http_header03 && $http_header03 =~ s/\QReferer\x3A \E/^/i ) { $http_header03 =~ s/\Q\x0D\x0A\E/\$/i; $pcrereferer = $http_header03; undef $http_header03 }
     if( $http_header13 && $http_header13 =~ s/\Q^Referer\x3A\x20\E/^/i ) { $http_header13=~s/\Q\x0D\x0A\E/\$/i;   $pcrereferer = $http_header13; undef $http_header13 }
  elsif( $http_header13 && $http_header13 =~ s/\Q^Referer\x3A \E/^/i ) { $http_header13=~s/\Q\x0D\x0A\E/\$/i;   $pcrereferer = $http_header13; undef $http_header13 }
  elsif( $http_header13 && $http_header13 =~ s/\QReferer\x3A\x20\E/^/i ) { $http_header13=~s/\Q\x0D\x0A\E/\$/i;   $pcrereferer = $http_header13; undef $http_header13 }
  elsif( $http_header13 && $http_header13 =~ s/\QReferer\x3A \E/^/i ) { $http_header13=~s/\Q\x0D\x0A\E/\$/i;   $pcrereferer = $http_header13; undef $http_header13 }
     if( $http_header23 && $http_header23 =~ s/\Q^Referer\x3A\x20\E/^/i ) { $http_header23 =~ s/\Q\x0D\x0A\E/\$/i; $pcrereferer = $http_header23; undef $http_header23 }
  elsif( $http_header23 && $http_header23 =~ s/\Q^Referer\x3A \E/^/i ) { $http_header23 =~ s/\Q\x0D\x0A\E/\$/i; $pcrereferer = $http_header23; undef $http_header23 }
  elsif( $http_header23 && $http_header23 =~ s/\QReferer\x3A\x20\E/^/i ) { $http_header23 =~ s/\Q\x0D\x0A\E/\$/i; $pcrereferer = $http_header23; undef $http_header23 }
  elsif( $http_header23 && $http_header23 =~ s/\QReferer\x3A \E/^/i ) { $http_header23 =~ s/\Q\x0D\x0A\E/\$/i; $pcrereferer = $http_header23; undef $http_header23 }
     if( $pcre_agent34  && $pcre_agent34  =~ s/\Q^Referer\x3A\x20\E/^/i ) { $pcre_agent34 =~ s/\Q\x0D\x0A\E/\$/i;  $pcrereferer = $pcre_agent34; undef $pcre_agent34 }
  elsif( $pcre_agent34  && $pcre_agent34  =~ s/\Q^Referer\x3A \E/^/i ) { $pcre_agent34 =~ s/\Q\x0D\x0A\E/\$/i;  $pcrereferer = $pcre_agent34; undef $pcre_agent34 }
  elsif( $pcre_agent34  && $pcre_agent34  =~ s/\QReferer\x3A\x20\E/^/i ) { $pcre_agent34 =~ s/\Q\x0D\x0A\E/\$/i;  $pcrereferer = $pcre_agent34; undef $pcre_agent34 }
  elsif( $pcre_agent34  && $pcre_agent34  =~ s/\QReferer\x3A \E/^/i ) { $pcre_agent34 =~ s/\Q\x0D\x0A\E/\$/i;  $pcrereferer = $pcre_agent34; undef $pcre_agent34 }

     if( $http_header03 && $http_header03 =~ s/\Q\x0d\x0aCookie\x3A \E(?!$)/^/i ) { $cookie = $http_header03; undef $http_header03 }
  elsif( $http_header03 && $http_header03 =~ s/\QCookie\x3A \E(?!$)/^/i ) { $cookie = $http_header03; undef $http_header03 }
  elsif( $http_header03 && $http_header03 =~ s/\Q\x0d\x0aCookie\x3A\x20\E(?!$)/^/i ) { $cookie = $http_header03; undef $http_header03 }
  elsif( $http_header03 && $http_header03 =~ s/\QCookie\x3A\x20\E(?!$)/^/i ) { $cookie = $http_header03; undef $http_header03 }
  elsif( $http_header03 && $http_header03 =~ s/\Q\x0d\x0aCookie: \E(?!$)/^/i ) { $cookie = $http_header03; undef $http_header03 }
  elsif( $http_header03 && $http_header03 =~ s/\QCookie: \E(?!$)/^/i ) { $cookie = $http_header03; undef $http_header03 }
  elsif( $http_header03 && $http_header03 =~ s/\Q\x0d\x0aCookie:\x20\E(?!$)/^/i ) { $cookie = $http_header03; undef $http_header03 }
  elsif( $http_header03 && $http_header03 =~ s/\QCookie:\x20\E(?!$)/^/i ) { $cookie = $http_header03; undef $http_header03 }
     #if( $http_header03 && $http_header03 =~ s/\Q\x0D\x0A\E/\$/i ) { $cookie = $http_header03; undef $http_header03 }
     if( $http_header13 && $http_header13 =~ s/\Q\x0d\x0aCookie\x3A \E(?!$)/^/i ) { $cookie = $http_header13; undef $http_header13 }
  elsif( $http_header13 && $http_header13 =~ s/\QCookie\x3A \E(?!$)/^/i ) { $cookie = $http_header13; undef $http_header13 }
  elsif( $http_header13 && $http_header13 =~ s/\Q\x0d\x0aCookie\x3A\x20\E(?!$)/^/i ) { $cookie = $http_header13; undef $http_header13 }
  elsif( $http_header13 && $http_header13 =~ s/\QCookie\x3A\x20\E(?!$)/^/i ) { $cookie = $http_header13; undef $http_header13 }
  elsif( $http_header13 && $http_header13 =~ s/\Q\x0d\x0aCookie: \E(?!$)/^/i ) { $cookie = $http_header13; undef $http_header13 }
  elsif( $http_header13 && $http_header13 =~ s/\QCookie: \E(?!$)/^/i ) { $cookie = $http_header13; undef $http_header13 }
  elsif( $http_header13 && $http_header13 =~ s/\Q\x0d\x0aCookie:\x20\E(?!$)/^/i ) { $cookie = $http_header13; undef $http_header13 }
  elsif( $http_header13 && $http_header13 =~ s/\QCookie:\x20\E(?!$)/^/i ) { $cookie = $http_header13; undef $http_header13 }
     #if( $http_header13 && $http_header13 =~ s/\Q\x0D\x0A\E/\$/i ) { $cookie = $http_header13; undef $http_header13 }
     if( $http_header23 && $http_header23 =~ s/\Q\x0d\x0aCookie\x3A \E(?!$)/^/i ) { $cookie = $http_header23; undef $http_header23 }
  elsif( $http_header23 && $http_header23 =~ s/\QCookie\x3A \E(?!$)/^/i ) { $cookie = $http_header23; undef $http_header23 }
  elsif( $http_header23 && $http_header23 =~ s/\Q\x0d\x0aCookie\x3A\x20\E(?!$)/^/i ) { $cookie = $http_header23; undef $http_header23 }
  elsif( $http_header23 && $http_header23 =~ s/\QCookie\x3A\x20\E(?!$)/^/i ) { $cookie = $http_header23; undef $http_header23 }
  elsif( $http_header23 && $http_header23 =~ s/\Q\x0d\x0aCookie: \E(?!$)/^/i ) { $cookie = $http_header23; undef $http_header23 }
  elsif( $http_header23 && $http_header23 =~ s/\QCookie: \E(?!$)/^/i ) { $cookie = $http_header23; undef $http_header23 }
  elsif( $http_header23 && $http_header23 =~ s/\Q\x0d\x0aCookie:\x20\E(?!$)/^/i ) { $cookie = $http_header23; undef $http_header23 }
  elsif( $http_header23 && $http_header23 =~ s/\QCookie:\x20\E(?!$)/^/i ) { $cookie = $http_header23; undef $http_header23 }
     #if( $http_header23 && $http_header23 =~ s/\Q\x0D\x0A\E/\$/i ) { $cookie = $http_header23; undef $http_header23 }
     if( $pcre_agent34  && $pcre_agent34  =~ s/\Q\x0d\x0aCookie\x3A \E(?!$)/^/i ) { $cookie = $pcre_agent34; undef $pcre_agent34 }
  elsif( $pcre_agent34  && $pcre_agent34  =~ s/\QCookie\x3A \E(?!$)/^/i ) { $cookie = $pcre_agent34; undef $pcre_agent34 }
  elsif( $pcre_agent34  && $pcre_agent34 =~ s/\Q\x0d\x0aCookie\x3A\x20\E(?!$)/^/i ) { $cookie = $pcre_agent34; undef $pcre_agent34 }
  elsif( $pcre_agent34  && $pcre_agent34 =~ s/\QCookie\x3A\x20\E(?!$)/^/i ) { $cookie = $pcre_agent34; undef $pcre_agent34 }
  elsif( $pcre_agent34  && $pcre_agent34 =~ s/\Q\x0d\x0aCookie: \E(?!$)/^/i ) { $cookie = $pcre_agent34; undef $pcre_agent34 }
  elsif( $pcre_agent34  && $pcre_agent34 =~ s/\QCookie: \E(?!$)/^/i ) { $cookie = $pcre_agent34; undef $pcre_agent34 }
  elsif( $pcre_agent34  && $pcre_agent34 =~ s/\Q\x0d\x0aCookie:\x20\E(?!$)/^/i ) { $cookie = $pcre_agent34; undef $pcre_agent34 }
  elsif( $pcre_agent34  && $pcre_agent34 =~ s/\QCookie:\x20\E(?!$)/^/i ) { $cookie = $pcre_agent34; undef $pcre_agent34 }
     #if( $pcre_agent34  && $pcre_agent34 =~ s/\Q\x0D\x0A\E/\$/i ) { $cookie = $pcre_agent34; undef $pcre_agent34 }

  $http_header03 =~ s/\Q\x0D\x0A\E/\$/i if $http_header03; # http_header, \x0D\x0A
  $http_header13 =~ s/\Q\x0D\x0A\E/\$/i if $http_header13; # http_header, \x0D\x0A
  $http_header23 =~ s/\Q\x0D\x0A\E/\$/i if $http_header23; # http_header, \x0D\x0A
  $pcre_agent34 =~ s/\Q\x0D\x0A\E/\$/i if $pcre_agent34; # http_header, \x0D\x0A
  $cookie =~ s/\Q\x0D\x0A\E/\$/i if $cookie; # http_header, \x0D\x0A

  if( $pcre_agent34 )
  {
   $pcre_agent34 =~ s/\Q^[^\r\n]+?\E//i;
   $pcre_agent34 =~ s/\Q^[^\r\n]+\E//i;
   $pcre_agent34 =~ s/\Q^[^\r\n]*?\E//i;
   $pcre_agent34 =~ s/\Q^[^\r\n]*\E//i;
   $pcre_agent34 =~ s/\Q^[^\n]+?\E//i;
   $pcre_agent34 =~ s/\Q^[^\n]+\E//i;
   $pcre_agent34 =~ s/\Q^[^\n]*?\E//i;
   $pcre_agent34 =~ s/\Q^[^\n]*\E//i;
  }

  if( $pcre_uri33 )
  {
   $pcre_uri33 =~ s/^\^\\\//\^(?:https?\\\:\\\/\\\/)?[^\\\/]*?\\\//i;
   $pcre_uri33 =~ s/^\^\\x2F/\^(?:https?\\\:\\\/\\\/)?[^\\\/]*?\\x2F/i;
  }

  my $okremiseazeropcreagent34=0;
  if( $pcre_agent34 && $http_header03 && ( $pcre_agent34 =~ /^\^\[\^(?:\\r)?\\n(?:\\r)?\]\+(.*)$/ ) && ( $http_header03 eq $1 ) ) { $okremiseazeropcreagent34=1 }
  if( $pcre_agent34 && $http_header13 && ( $pcre_agent34 =~ /^\^\[\^(?:\\r)?\\n(?:\\r)?\]\+(.*)$/ ) && ( $http_header13 eq $1 ) ) { $okremiseazeropcreagent34=1 }
  if( $pcre_agent34 && $http_header23 && ( $pcre_agent34 =~ /^\^\[\^(?:\\r)?\\n(?:\\r)?\]\+(.*)$/ ) && ( $http_header23 eq $1 ) ) { $okremiseazeropcreagent34=1 }

  # http_user_agent short
  if( $http_header03 && $http_header13 && $http_header23 && length($http_header03) >= ( length($http_header13) or length($http_header23) ) )
  {
   $httpagentshort= "$http_header03" if $http_header03;
  }
  elsif( $http_header03 && $http_header13 && $http_header23 && length($http_header13) >= ( length($http_header03) or length($http_header23) ) )
  {
   $httpagentshort= "$http_header13" if $http_header13;
  }
  elsif( $http_header03 && $http_header13 && $http_header23 && length($http_header23) >= ( length($http_header03) or length($http_header13) ) )
  {
   $httpagentshort= "$http_header23" if $http_header23;
  }
  elsif( $http_header03 && $http_header13 && !$http_header23 && length($http_header03) >= length($http_header13) )
  {
   $httpagentshort= "$http_header03" if $http_header03;
  }
  elsif( $http_header03 && $http_header13 && !$http_header23 && length($http_header13) >= length($http_header03) )
  {
   $httpagentshort= "$http_header13" if $http_header13;
  }
  elsif( !$http_header03 && $http_header13 && $http_header23 && length($http_header13) >= length($http_header23) )
  {
   $httpagentshort= "$http_header13" if $http_header13;
  }
  elsif( !$http_header03 && $http_header13 && $http_header23 && length($http_header23) >= length($http_header13) )
  {
   $httpagentshort= "$http_header23" if $http_header23;
  }
  elsif( $http_header03 && !$http_header13 && $http_header23 && length($http_header03) >= length($http_header23) )
  {
   $httpagentshort= "$http_header03" if $http_header03;
  }
  elsif( $http_header03 && !$http_header13 && $http_header23 && length($http_header23) >= length($http_header03) )
  {
   $httpagentshort= "$http_header23" if $http_header23;
  }
  elsif( $http_header03 && !$http_header13 && !$http_header23 )
  {
   $httpagentshort= "$http_header03" if $http_header03;
  }
  elsif( !$http_header03 && $http_header13 && !$http_header23 )
  {
   $httpagentshort= "$http_header13" if $http_header13;
  }
  elsif( !$http_header03 && !$http_header13 && $http_header23 )
  {
   $httpagentshort= "$http_header23" if $http_header23;
  }
  while( $httpagentshort =~ /\\x(..)/g )
  {
   my $tempochr=chr(hex("$1"));
   $httpagentshort =~ s/\\x(..)/$tempochr/;
  }
  $httpagentshort =~ s/(?:\\|\^|\$)//g;

  if( $pcre_agent34 && $http_header03 && $pcre_agent34=~/\Q$http_header03\E/i ) {
   undef $http_header03;
   print "ok trouver grep3a\n" if $debug1;
  }
  elsif( $pcre_agent34 && $http_header03 && $http_header03=~s/\&/\\x26/g && $pcre_agent34=~/\Q$http_header03\E/i ) {
   undef $http_header03;
   print "ok trouver grep3b\n" if $debug1;
  }
  elsif( $pcre_agent34 && $http_header03 && $http_header03=~s/\=/\\x3D/g && $pcre_agent34=~/\Q$http_header03\E/i ) {
   undef $http_header03;
   print "ok trouver grep3c\n" if $debug1;
  }
  if( $pcre_uri33 && $http_uri08 && $pcre_uri33=~/\Q$http_uri08\E/i ) {
   undef $http_uri08;
   print "ok trouver grep8a\n" if $debug1;
  }
  elsif( $pcre_uri33 && $http_uri08 && $http_uri08=~s/\&/\\x26/g && $pcre_uri33=~/\Q$http_uri08\E/i ) {
   undef $http_uri08;
   print "ok trouver grep8b\n" if $debug1;
  }
  elsif( $pcre_uri33 && $http_uri08 && $http_uri08=~s/\=/\\x3D/g && $pcre_uri33=~/\Q$http_uri08\E/i ) {
   undef $http_uri08;
   print "ok trouver grep8c\n" if $debug1;
  }
  if( $pcre_agent34 && $http_header13 && $pcre_agent34=~/\Q$http_header13\E/i ) {
   undef $http_header13;
   print "ok trouver grep13a\n" if $debug1;
  }
  elsif( $pcre_agent34 && $http_header13 && $http_header13=~s/\&/\\x26/g && $pcre_agent34=~/\Q$http_header13\E/i ) {
   undef $http_header13;
   print "ok trouver grep13b\n" if $debug1;
  }
  elsif( $pcre_agent34 && $http_header13 && $http_header13=~s/\=/\\x3D/g && $pcre_agent34=~/\Q$http_header13\E/i ) {
   undef $http_header13;
   print "ok trouver grep13c\n" if $debug1;
  }
  if( $pcre_uri33 && $http_uri18 && $pcre_uri33=~/\Q$http_uri18\E/i ) {
   undef $http_uri18;
   print "ok trouver grep18\n" if $debug1;
  }
  elsif( $pcre_uri33 && $http_uri18 && $http_uri18=~s/\&/\\x26/g && $pcre_uri33=~/\Q$http_uri18\E/i ) {
   undef $http_uri18;
   print "ok trouver grep18\n" if $debug1;
  }
  elsif( $pcre_uri33 && $http_uri18 && $http_uri18=~s/\=/\\x3D/g && $pcre_uri33=~/\Q$http_uri18\E/i ) {
   undef $http_uri18;
   print "ok trouver grep18\n" if $debug1;
  }
  if( $pcre_agent34 && $http_header23 && $pcre_agent34=~/\Q$http_header23\E/i ) {
   undef $http_header23;
   print "ok trouver grep23\n" if $debug1;
  }
  elsif( $pcre_agent34 && $http_header23 && $http_header23=~s/\&/\\x26/g && $pcre_agent34=~/\Q$http_header23\E/i ) {
   undef $http_header23;
   print "ok trouver grep23\n" if $debug1;
  }
  elsif( $pcre_agent34 && $http_header23 && $http_header23=~s/\=/\\x3D/g && $pcre_agent34=~/\Q$http_header23\E/i ) {
   undef $http_header23;
   print "ok trouver grep23\n" if $debug1;
  }
  if( $pcre_uri33 && $http_uri28 && $pcre_uri33=~/\Q$http_uri28\E/i ) {
   undef $http_uri28;
   print "ok trouver grep28\n" if $debug1;
  }
  elsif( $pcre_uri33 && $http_uri28 && $http_uri28=~s/\&/\\x26/g && $pcre_uri33=~/\Q$http_uri28\E/i ) {
   undef $http_uri28;
   print "ok trouver grep28\n" if $debug1;
  }
  elsif( $pcre_uri33 && $http_uri28 && $http_uri28=~s/\=/\\x3D/g && $pcre_uri33=~/\Q$http_uri28\E/i ) {
   undef $http_uri28;
   print "ok trouver grep28\n" if $debug1;
  }

  # one header
  $httppcreagent= "$http_header03" if $http_header03 && !$http_header13 && !$http_header23 && !$pcre_agent34;
  $httppcreagent= "$http_header13" if $http_header13 && !$http_header03 && !$http_header23 && !$pcre_agent34;
  $httppcreagent= "$http_header23" if $http_header23 && !$http_header03 && !$http_header13 && !$pcre_agent34;
  $httppcreagent= "$pcre_agent34" if $pcre_agent34 && !$http_header03 && !$http_header13 && !$http_header23;
  unless( $httppcreagent && ($httppcreagent =~/(?:\\|\^|\$)/) ) { $httppcreagent=0 }

  # one uri
  #$abc1= "$http_uri08" if $http_uri08 && !$http_uri18 && !$http_uri28;
  #$abc1= "$http_uri18" if $http_uri18 && !$http_uri08 && !$http_uri28;
  #$abc1= "$http_uri28" if $http_uri28 && !$http_uri08 && !$http_uri18;
  $abc1= "$pcre_uri33" if $pcre_uri33 && !$http_uri08 && !$http_uri18;

  # two headers
  if( (defined($distance14)||defined($distance15)||defined($distance16)||defined($distance17)) && !(defined($distance24)||defined($distance25)||defined($distance26)||defined($distance27)) ) {
   $httppcreagent= "(?:$http_header03.*?$http_header13)" if $http_header03 && $http_header13 && !$http_header23 && !$pcre_agent34;
  }
  elsif( !(defined($distance14)||defined($distance15)||defined($distance16)||defined($distance17)) && !(defined($distance24)||defined($distance25)||defined($distance26)||defined($distance27)) ) {
   $httppcreagent= "(?:$http_header03.*?$http_header13|$http_header13.*?$http_header03)" if $http_header03 && $http_header13 && !$http_header23 && !$pcre_agent34;
   $httppcreagent= "(?:$http_header03.*?$http_header23|$http_header23.*?$http_header03)" if $http_header03 && $http_header23 && !$http_header13 && !$pcre_agent34;
   $httppcreagent= "(?:$http_header03.*?$pcre_agent34|$pcre_agent34.*?$http_header03)" if $http_header03 && $pcre_agent34 && !$http_header13 && !$http_header23;
  }

  # two uri
  if( (defined($distance19)||defined($distance20)||defined($distance21)||defined($distance22)) && !(defined($distance29)||defined($distance30)||defined($distance31)||defined($distance32)) ) {
   $abc1= "(?:$http_uri08.*?$http_uri18)" if $http_uri08 && $http_uri18 && !$http_uri28 && !$pcre_uri33;
  }
  elsif( !(defined($distance19)||defined($distance20)||defined($distance21)||defined($distance22)) && !(defined($distance29)||defined($distance30)||defined($distance31)||defined($distance32)) ) {
   if( $http_uri08 && $http_uri18 && !$http_uri28 && !$pcre_uri33 && (( $http_uri08 !~ /\\x|^\^|\$$/ ) or ( $http_uri18 !~ /\\x|^\^|\$$/ )) )
   {
    @tableauuri1 = ( $http_uri08, $http_uri18 ) if $http_uri08 && $http_uri18 && !$pcre_uri33;
    my $tableauuri1index=0;
    foreach( @tableauuri1 )
    {
     $tableauuri1[$tableauuri1index++] =~ s/\\(?!x)//g;
     if( $_ =~ /\\x|^\^|\$$/ ) { undef @tableauuri1 }
    }
   }
   else
   {
    $abc1= "(?:$http_uri08.*?$http_uri18|$http_uri18.*?$http_uri08)" if $http_uri08 && $http_uri18 && !$http_uri28 && !$pcre_uri33;
   }

   $abc1= "(?:$http_uri08.*?$pcre_uri33|$pcre_uri33.*?$http_uri08)" if $http_uri08 && $pcre_uri33 && !$http_uri18 && !$http_uri28;
  }

  # three headers
  if( (defined($distance14)||defined($distance15)||defined($distance16)||defined($distance17)) && (defined($distance24)||defined($distance25)||defined($distance26)||defined($distance27)) ) {
   $httppcreagent= "(?:$http_header03.*$http_header13.*$http_header23)" if $http_header03 && $http_header13 && $http_header23 && !$pcre_agent34;
  }
  elsif( !(defined($distance14)||defined($distance15)||defined($distance16)||defined($distance17)) && !(defined($distance24)||defined($distance25)||defined($distance26)||defined($distance27)) ) {
   $httppcreagent= "(?:$http_header03.*$http_header13.*$http_header23|$http_header03.*$http_header23.*$http_header13|$http_header23.*$http_header03.*$http_header13|$http_header23.*$http_header13.*$http_header03)" if $http_header03 && $http_header13 && $http_header23 && !$pcre_agent34;
   $httppcreagent= "(?:$http_header03.*$http_header13.*$pcre_agent34|$http_header03.*$pcre_agent34.*$http_header13|$pcre_agent34.*$http_header03.*$http_header13|$pcre_agent34.*$http_header13.*$http_header03)" if $http_header03 && $http_header13 && $pcre_agent34 && !$http_header23;
  }

  # three uri
  if( (defined($distance19)||defined($distance20)||defined($distance21)||defined($distance22)) && (defined($distance29)||defined($distance30)||defined($distance31)||defined($distance32)) ) {
   $abc1= "(?:$http_uri08.*$http_uri18.*$pcre_uri33)" if $http_uri08 && $http_uri18 && $pcre_uri33 && !$http_uri28;
  }
  elsif( !(defined($distance19)||defined($distance20)||defined($distance21)||defined($distance22)) && !(defined($distance29)||defined($distance30)||defined($distance31)||defined($distance32)) ) {
   if( $http_uri08 && $http_uri18 && $http_uri28 && !$pcre_uri33 && (( $http_uri08 !~ /\\x|^\^|\$$/ ) or ( $http_uri18 !~ /\\x|^\^|\$$/ ) or ( $http_uri28 !~ /\\x|^\^|\$$/ )) )
   {
    @tableauuri1 = ( $http_uri08, $http_uri18, $http_uri28 ) if $http_uri08 && $http_uri18 && $http_uri28 && !$pcre_uri33;
    my $tableauuri1index=0;
    foreach( @tableauuri1 )
    {
     $tableauuri1[$tableauuri1index++] =~ s/\\(?!x)//g;
     if( $_ =~ /\\x|^\^|\$$/ ) { undef @tableauuri1 }
    }
   }
   else
   {
   $abc1= "(?:$http_uri08.*$http_uri18.*$http_uri28|$http_uri08.*$http_uri28.*$http_uri18|$http_uri28.*$http_uri08.*$http_uri18|$http_uri28.*$http_uri18.*$http_uri08)" if $http_uri08 && $http_uri18 && $http_uri28 && !$pcre_uri33;
   }
   $abc1= "(?:$http_uri08.*$http_uri18.*$pcre_uri33|$http_uri08.*$pcre_uri33.*$http_uri18|$pcre_uri33.*$http_uri08.*$http_uri18|$pcre_uri33.*$http_uri18.*$http_uri08)" if $http_uri08 && $http_uri18 && $pcre_uri33 && !$http_uri28;
  }

  # four headers
   $httppcreagent= "(?:$http_header03.*$http_header13.*$http_header23.*$pcre_agent34|$http_header03.*$http_header13.*$pcre_agent34.*$http_header23|$http_header03.*$http_header23.*$http_header13.*$pcre_agent34|$http_header03.*$http_header23.*$pcre_agent34.*$http_header13|$http_header13.*$http_header23.*$pcre_agent34.*$http_header03|$http_header13.*$http_header23.*$http_header03.*$pcre_agent34|$http_header13.*$http_header03.*$http_header23.*$pcre_agent34|$http_header13.*$http_header03.*$pcre_agent34.*$http_header23|$http_header23.*$http_header03.*$http_header13.*$pcre_agent34|$http_header23.*$http_header03.*$pcre_agent34.*$http_header13|$http_header23.*$http_header13.*$pcre_agent34.*$http_header03|$http_header23.*$http_header13.*$http_header03.*$pcre_agent34|$pcre_agent34.*$http_header03.*$http_header13.*$http_header23|$pcre_agent34.*$http_header03.*$http_header23.*$http_header13|$pcre_agent34.*$http_header23.*$http_header03.*$http_header13|$pcre_agent34.*$http_header23.*$http_header13.*$http_header03)" if $http_header03 && $http_header13 && $http_header23 && $pcre_agent34;

  # four uri
   $abc1= "(?:$http_uri08.*$http_uri18.*$http_uri28.*$pcre_uri33|$http_uri08.*$http_uri18.*$pcre_uri33.*$http_uri28|$http_uri08.*$http_uri28.*$http_uri18.*$pcre_uri33|$http_uri08.*$http_uri28.*$pcre_uri33.*$http_uri18|$http_uri18.*$http_uri28.*$pcre_uri33.*$http_uri08|$http_uri18.*$http_uri28.*$http_uri08.*$pcre_uri33|$http_uri18.*$http_uri08.*$http_uri28.*$pcre_uri33|$http_uri18.*$http_uri08.*$pcre_uri33.*$http_uri28|$http_uri28.*$http_uri08.*$http_uri18.*$pcre_uri33|$http_uri28.*$http_uri08.*$pcre_uri33.*$http_uri18|$http_uri28.*$http_uri18.*$pcre_uri33.*$http_uri08|$http_uri28.*$http_uri18.*$http_uri08.*$pcre_uri33|$pcre_uri33.*$http_uri08.*$http_uri18.*$http_uri28|$pcre_uri33.*$http_uri08.*$http_uri28.*$http_uri18|$pcre_uri33.*$http_uri28.*$http_uri08.*$http_uri18|$pcre_uri33.*$http_uri28.*$http_uri18.*$http_uri08)" if $http_uri08 && $http_uri18 && $http_uri28 && $pcre_uri33;

  if( $okremiseazeropcreagent34 ) { undef $httppcreagent }

  # uri:
  my $abc1_nocase=0;
     $abc1_nocase=$http_urifast14   if $http_urifast14;
     $abc1_nocase=$http_urinocase12 if $http_urinocase12;
     $abc1_nocase=$http_urifast18   if $http_urifast18;
     $abc1_nocase=$http_urinocase15 if $http_urinocase15;
     $abc1_nocase=$http_urifast32   if $http_urifast32;
     $abc1_nocase=$http_urinocase25 if $http_urinocase25;
     $abc1_nocase=$http_urifast36   if $http_urifast36;
     $abc1_nocase=$http_urinocase28 if $http_urinocase28;
     $abc1_nocase=$http_urifast50   if $http_urifast50;
     $abc1_nocase=$http_urinocase39 if $http_urinocase39;
     $abc1_nocase=$http_urifast54   if $http_urifast54;
     $abc1_nocase=$http_urinocase42 if $http_urinocase42;
  # header:
  my $httppcreagent_nocase=0;
     $httppcreagent_nocase=$http_headerfast5    if $http_headerfast5;
     $httppcreagent_nocase=$http_headernocase5  if $http_headernocase5;
     $httppcreagent_nocase=$http_headerfast9    if $http_headerfast9;
     $httppcreagent_nocase=$http_headernocase8  if $http_headernocase8;
     $httppcreagent_nocase=$http_headerfast23   if $http_headerfast23;
     $httppcreagent_nocase=$http_headernocase19 if $http_headernocase19;
     $httppcreagent_nocase=$http_headerfast27   if $http_headerfast27;
     $httppcreagent_nocase=$http_headernocase22 if $http_headernocase22;
     $httppcreagent_nocase=$http_headerfast41   if $http_headerfast41;
     $httppcreagent_nocase=$http_headernocase32 if $http_headernocase32;
     $httppcreagent_nocase=$http_headerfast45   if $http_headerfast45;
     $httppcreagent_nocase=$http_headernocase35 if $http_headernocase35;

  if( $httpagentshort && $httppcreagent )
  {
   my $tempopcreagent = $httppcreagent;
   $tempopcreagent =~ s/\\//g;
   if( $httpagentshort eq $tempopcreagent )
   {
    print "tempopcreagent: $tempopcreagent\n" if $debug1;
    undef $httppcreagent;
    undef $tempopcreagent;
   }
  }

  print "httpuricourt4: $etmsg1, $httpuricourt\n" if $debug1 && $httpuricourt;
  print "httpurilong4: $etmsg1, @tableauuri1\n" if $debug1 && @tableauuri1;
  print "tableaupcreuri4: $etmsg1, $abc1\n" if $debug1 && $abc1;
  print "tableaupcreagent4: $etmsg1, $httppcreagent\n" if $debug1 && $httppcreagent;
  print "httpagentshort4: $etmsg1, $httpagentshort\n" if $debug1 && $httpagentshort;
  print "tableauhttpmethod4: $etmsg1, $http_method2\n" if $debug1 && $http_method2;
  print "tableaupcrereferer4: $etmsg1, $pcrereferer\n" if $debug1 && $pcrereferer;
  print "tableaupcrecookie4: $etmsg1, $cookie\n" if $debug1 && $cookie;

  $hash{$etmsg1}{httpuricourt} = [ $httpuricourt ] if $httpuricourt;
  $hash{$etmsg1}{httpagentshort} = [ $httpagentshort ] if $httpagentshort;
  $hash{$etmsg1}{httpmethod} = [ $http_method2, $http_methodnocase3 ] if $http_method2;
  $hash{$etmsg1}{pcrereferer} = [ $pcrereferer ] if $pcrereferer;
  $hash{$etmsg1}{pcreuri} = [ $abc1, $abc1_nocase ] if $abc1;
  $hash{$etmsg1}{pcreagent} = [ $httppcreagent, $httppcreagent_nocase ] if $httppcreagent;
  $hash{$etmsg1}{pcrecookie} = [ $cookie ] if $cookie;
  $hash{$etmsg1}{httpurilong} = [ @tableauuri1 ] if @tableauuri1;

  next;
 }


 # begin http_uri followed by http_cookie
 elsif( $_=~ /^\s*alert\s+(?:udp|tcp)\s+\S+\s+\S+\s+\-\>\s+$category\s+\S+\s+\(\s*msg\:\s*\"([^\"]*?)\"\s*\;\s*(?:$flow1)?(?:$httpmethod)?(?:\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)?\s*http_uri\;(?:$contentoptions1)?(?:$negateuricontent1)?)?\s*content\:\s*\"([^\"]*?)\"\s*\;(?:$contentoptions1)?\s*http_cookie\;(?:$contentoptions1)?(?:$negateuricontent1)?(?:$extracontentoptions)?(?:$pcreuri)?(?:$extracontentoptions)?$referencesidrev$/ )
 {
  my $etmsg1=$1;
  my $http_method2=0;
  my $http_methodnocase3=0;
  print "brut5: $_\n" if $debug1;
  #print "here5: $1, $2, $3, $4, 5: $5, $6, $7, $8, $9, 10: $10, 11: $11, $12, 13: $13, $14, 15: $15, $16, $17, $18, $19, 20: $20, $21, $22\n" if $debug1;

     $http_method2=$2 if $2;
     $http_methodnocase3=$3 if $3;
  my $http_uri03=$4 if $4;
  my $http_urinocase5=$6 if $6;
  my $http_urinocase8=$10 if $10;
  my $http_cookie=$13 if $13;
  my $http_cookienocase12=$15 if $15;
  my $http_cookienocase15=$19 if $19;
  my $pcre_uri13=$22 if $22;

  # check what is http_uri best length ?
  my $httpuricourt=0;
     $httpuricourt=$http_uri03 if $http_uri03;

  $http_uri03 =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_uri03; # (
  $http_uri03 =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_uri03; # )
  $http_uri03 =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_uri03; # *
  $http_uri03 =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_uri03; # +
  $http_uri03 =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_uri03; # -
  $http_uri03 =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_uri03; # .
  $http_uri03 =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_uri03; # /
  $http_uri03 =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_uri03; # ?
  $http_uri03 =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_uri03; # [
  $http_uri03 =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_uri03; # ]
  $http_uri03 =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_uri03; # ^
  $http_uri03 =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_uri03; # {
  $http_uri03 =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_uri03; # }
  $http_cookie =~ s/(?<!\x5C)\x28/\x5C\x28/g if $http_cookie; # (
  $http_cookie =~ s/(?<!\x5C)\x29/\x5C\x29/g if $http_cookie; # )
  $http_cookie =~ s/(?<!\x5C)\x2A/\x5C\x2A/g if $http_cookie; # *
  $http_cookie =~ s/(?<!\x5C)\x2B/\x5C\x2B/g if $http_cookie; # +
  $http_cookie =~ s/(?<!\x5C)\x2D/\x5C\x2D/g if $http_cookie; # -
  $http_cookie =~ s/(?<!\x5C)\x2E/\x5C\x2E/g if $http_cookie; # .
  $http_cookie =~ s/(?<!\x5C)\x2F/\x5C\x2F/g if $http_cookie; # /
  $http_cookie =~ s/(?<!\x5C)\x3F/\x5C\x3F/g if $http_cookie; # ?
  $http_cookie =~ s/(?<!\x5C)\x5B/\x5C\x5B/g if $http_cookie; # [
  $http_cookie =~ s/(?<!\x5C)\x5D/\x5C\x5D/g if $http_cookie; # ]
  $http_cookie =~ s/(?<!\x5C)\x5E/\x5C\x5E/g if $http_cookie; # ^
  $http_cookie =~ s/(?<!\x5C)\x7B/\x5C\x7B/g if $http_cookie; # {
  $http_cookie =~ s/(?<!\x5C)\x7D/\x5C\x7D/g if $http_cookie; # }
  #$pcre_uri13 =~ s/(?<!\x5C)\x24//g         if $pcre_uri13; # $
#perl -e '$abc1="1|20 21|2|22 24|3";while($abc1=~/(?<!\x5C)\|(.*?)\|/g){$toto1=$1;print "abc1:$abc1\ntoto1:$toto1\n";$toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g; print "$toto1\n"; $abc1=~s/(?<!\x5C)\|.*?\|/$toto1/}; print "final:$abc1\n"'
  while($http_uri03 && $http_uri03=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_uri03=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  while($http_cookie && $http_cookie=~/(?<!\x5C)\|(.*?)\|/g) {
   my $toto1=$1;
   $toto1=~s/\s*([0-9A-Fa-f]{2})/\\x$1/g;
   $http_cookie=~s/(?<!\x5C)\|.*?\|/$toto1/;
  }
  # ne pas faire d'echappement sur la pcre ($pcre_uri13)
  my $abc1;
  my $cookie=0;

     if( $http_cookie && $http_cookie =~ s/\QCookie\x3A \E(?!$)/^/i ) { $cookie = $http_cookie; undef $http_cookie }
  elsif( $http_cookie && $http_cookie =~ s/\QCookie\x3A\x20\E(?!$)/^/i ) { $cookie = $http_cookie; undef $http_cookie }
  elsif( $http_cookie && $http_cookie =~ s/\QCookie: \E(?!$)/^/i ) { $cookie = $http_cookie; undef $http_cookie }
  elsif( $http_cookie && $http_cookie =~ s/\QCookie:\x20\E(?!$)/^/i ) { $cookie = $http_cookie; undef $http_cookie }
  $http_cookie =~ s/\Q\x0D\x0A\E/\$/i if $http_cookie; # http_cookie, \x0D\x0A

  if( $pcre_uri13 )
  {
   $pcre_uri13 =~ s/^\^\\\//\^(?:https?\\\:\\\/\\\/)?[^\\\/]*?\\\//i;
   $pcre_uri13 =~ s/^\^\\x2F/\^(?:https?\\\:\\\/\\\/)?[^\\\/]*?\\x2F/i;
  }

  if( $pcre_uri13 && $http_uri03 && $pcre_uri13=~/\Q$http_uri03\E/i ) {
   undef $http_uri03;
   print "ok trouver grep3\n" if $debug1;
  }
  elsif( $pcre_uri13 && $http_uri03 && $http_uri03=~s/\&/\\x26/g && $pcre_uri13=~/\Q$http_uri03\E/i ) {
   undef $http_uri03;
   print "ok trouver grep3\n" if $debug1;
  }
  elsif( $pcre_uri13 && $http_uri03 && $http_uri03=~s/\=/\\x3D/g && $pcre_uri13=~/\Q$http_uri03\E/i ) {
   undef $http_uri03;
   print "ok trouver grep3\n" if $debug1;
  }

  $abc1= "$http_uri03" if $http_uri03 && !$pcre_uri13;
  $abc1= "$pcre_uri13" if $pcre_uri13 && !$http_uri03;
  $abc1= "(?:$http_uri03.*?$pcre_uri13|$pcre_uri13.*?$http_uri03)" if $http_uri03 && $pcre_uri13;

  my $abc1_nocase=0;

  # cookie:
  my $http_cookie_nocase=0;
     $http_cookie_nocase=$http_cookienocase12 if $http_cookienocase12;
     $http_cookie_nocase=$http_cookienocase15 if $http_cookienocase15;

  print "httpuricourt5: $etmsg1, $httpuricourt\n" if $debug1 && $httpuricourt;
  print "tableaupcreuri5: $etmsg1, $abc1\n" if $debug1 && $abc1;
  print "tableauhttpmethod5: $etmsg1, $http_method2\n" if $debug1 && $http_method2;
  print "tableaupcrecookie5: $etmsg1, $http_cookie\n" if $debug1 && $http_cookie;

  #push( @tableauuricontent, ("$etmsg1", "$http_method2", "$http_methodnocase3" , "", "",    , "", "$abc1", "$abc1_nocase") ) if $abc1;

  $hash{$etmsg1}{httpuricourt} = [ $httpuricourt ] if $httpuricourt;
  $hash{$etmsg1}{pcreuri} = [ $abc1, $abc1_nocase ] if $abc1;
  $hash{$etmsg1}{httpmethod} = [ $http_method2, $http_methodnocase3 ] if $http_method2;
  $hash{$etmsg1}{pcrecookie} = [ $http_cookie, $http_cookie_nocase ] if $http_cookie;

  next;
 }

 else
 {
  print "erreur parsing signature: $_\n" if $debug1;
  next;
 }
}

print "####################################################################################\n" if $debug1;

my @threads = map threads->create(sub {
   #while (defined (my $_ = $queue->dequeue_nb()))  # for cat ... | perl etplc
   while ( defined (my $_ = $queue->dequeue()) ) {   # for tail -f ... | perl etplc

 chomp $_;
 $output_escape = printable($_);
 #print "rawproxy: $output_escape\n" if $debug2;

# squid default conf:
#2012-11-10T16:33:21.030867+01:00 hostname programname: 1352538457.034     79 192.168.2.3 TCP_MISS/200 2141 POST http://safe.google.com/downloads? - DIRECT/173.194.34.1 application/vnd.google.safe-update
#2012-11-10T16:33:21.031406+01:00 hostname programname: 1352538457.559     63 192.168.2.3 TCP_MISS/200 2688 GET http://safe-cache.google.com/safe/rd/ChNnb29ncIJyTBjIFl4kBAD8 - DIRECT/74.125.230.206 application/vnd.google.safebrowsing-chunk
#2012-11-10T16:33:21.031642+01:00 hostname programname: 1352538457.652    401 192.168.2.3 TCP_MISS/200 5472 CONNECT secure.infraton.com:443 - DIRECT/82.103.140.40 -
#2012-11-10T16:33:21.031658+01:00 hostname programname: 1352538457.776      4 192.168.2.3 TCP_MISS/404 449 GET http://89.9.8.8/ - DIRECT/89.9.8.8 text/html
#2012-11-10T16:33:21.032249+01:00 hostname programname: 1352538459.534     11 192.168.2.3 TCP_MISS/200 20207 GET http://safe-cache.google.com/safe/rd/ChFnohchAAGIGUDyCAqA8qugJVygMA______________________DzIPAcoDAP______9_____8P - DIRECT/74.125.230.206 application/vnd.google.safe-chunk
#2012-11-10T16:33:21.032448+01:00 hostname programname: 1352538486.175      0 192.168.2.3 TCP_MEM_HIT/200 2013 GET http://static.leboncoin.fr/img/logo.png - NONE/- image/png
#2012-11-10T16:33:21.035160+01:00 hostname programname: 1352538487.626    335 192.168.2.3 TCP_REFRESH_UNMODIFIED/200 80691 GET http://www.somantic.com/js/2010-07-01/adpan/google? - DIRECT/78.46.128.236 application/javascript
 if ( $output_escape =~ /^(?:\<\d+\>)?(\S+\s+\d+\s+\d+\:\d+\:\d+|\d+\-\d+\-\d+T\d+\:\d+\:\d+(?:\.\d+)?[\-\+]\d+\:\d+)\s(\S+)\s\S+\:\s(\d+\.\d+)\s+\d+\s+(\S+)\s+[A-Z\_]+\/(\d+)\s\d+\s+([A-Z]+)\s+(\S+)\s+\-\s+[A-Z]+\/(\S+)\s/ ) {
  $timestamp_central=$1; $proxy_hostname_ip=$2; $timestamp_unix=$3; $client_hostname_ip=$4; $proxy_http_reply_code=$5; $client_http_method=$6; $client_http_uri=$7; $web_hostname_ip=$8;
  $client_username="";
  print "passage dans premiere regexp.\n" if $debug2;
 }

# Squid added User-Agent:
#<179>Jan  9 00:05:34 hostname programname:   180 192.168.1.2 TCP_MISS/200 - [09/Jan/2013:00:05:25 +0100] 24375 GET http://www.mag-securs.com/images/Alertes_V2.jpg - DIRECT/93.93.190.66 image/jpeg \"Mozilla/5.0 (X11; Linux i686 on x86_64; rv:18.0) Gecko/20100101 Firefox/18.0\" \"http://www.mag-securs.com/articleId.aspx\"
#<179>Jan  8 23:42:32 hostname programname:   190 192.168.1.2 TCP_MISS/200 - [08/Jan/2013:23:42:24 +0100] 2109 GET http://www.mag-securs.com/BorderLayout.css - DIRECT/93.93.190.66 text/css \"Mozilla/5.0 (X11; Linux i686 on x86_64; rv:18.0) Gecko/20100101 Firefox/18.0\" \"http://www.mag-securs.com/\"
#2013-01-08T23:44:33.020912+01:00 hostname programname: 134640 192.168.1.2 TCP_MISS/200 - [08/Jan/2013:23:44:24 +0100] 30922 CONNECT www.google.fr:443 - DIRECT/173.194.34.55 - \"Mozilla/5.0 (X11; Linux i686 on x86_64; rv:18.0) Gecko/20100101 Firefox/18.0\" \"-\"
#2013-11-23T21:31:02.669653+01:00 hostname programname:     2 192.168.1.2 TCP_MISS/503 - [23/Nov/2013:21:30:58 +0100] 0 CONNECT www.marketscore.com:443 - HIER_NONE/- - "Wget/1.13.4 (linux-gnu)" "-" "-"
#2013-01-07T22:17:39.350724+01:00 hostname programname:    11 192.168.2.3 TCP_REFRESH_UNMODIFIED/304 - [07/Jan/2013:22:17:34 +0100] 286 GET http://mscrl.microsoft.com/pki/mscorp/crl/Microsoft%20Secure%20Server%20Authority(8).crl - DIRECT/94.245.70.118 application/pkix-crl \"Microsoft-CryptoAPI/6.0\" \"-\"
#2013-01-07T22:17:09.324890+01:00 hostname programname:   397 192.168.2.3 TCP_MISS/200 - [07/Jan/2013:22:17:03 +0100] 10945 GET http://appldnld.apple.com/iOS6/CarrierBundles/0ge_France_iPhone.ipcc - DIRECT/2.22.48.115 application/octet-stream \"iTunes/11.0.1 (Windows; Microsoft Windows Vista Home Premium Edition Service Pack 1 (Build 6001)) AppleWebKit/536.27.1\" \"-\"
#2013-01-07T21:30:26.791289+01:00 hostname programname:     1 192.168.2.3 TCP_MEM_HIT/200 - [07/Jan/2013:21:30:22 +0100] 15755 GET http://ax.init.itunes.apple.com/bag.xml? - NONE/- text/xml \"iTunes/11.0.1 (Windows; Microsoft Windows Vista Home Premium Edition Service Pack 1 (Build 6001)) AppleWebKit/536.27.1\" \"-\"
#2013-06-12T21:47:06.261557+02:00 hostname programname:   332 192.168.1.2 TCP_MISS/000 - [12/Jun/2013:21:46:57 +0200] 0 GET http://1.1.1.112/%67gu.php - DIRECT/1.1.1.112 - \"Wget/1.13.4 (linux-gnu)\" \"-\"
#2013-06-12T21:58:26.751411+02:00 hostname programname:   288 192.168.1.2 TCP_MISS/000 - [12/Jun/2013:21:58:23 +0200] 0 GET http://1.1.1.112/%67gu.php - DIRECT/1.1.1.112 - "Wget/1.13.4 (linux-gnu)" "-"
# add cookie:
# 2013-11-23T02:09:29.909623+01:00 hostname programname:   142 192.168.1.2 TCP_MISS/200 - [23/Nov/2013:02:09:22 +0100] 1890 GET http://etplc.org/ - HIER_DIRECT/etplc.org text/html "Wget/1.13.4 (linux-gnu)" "-" "fGGhTasdas=http"

 elsif ( $output_escape =~ /^(?:\<\d+\>)?(\S+\s+\d+\s+\d+\:\d+\:\d+|\d+\-\d+\-\d+T\d+\:\d+\:\d+(?:\.\d+)?[\-\+]\d+\:\d+)\s(\S+)\s\S+\:\s+\d+\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+[A-Z\_]+\/(\d+)\s+\-\s+\[(.*?)\]\s+\d+\s+([^\s]+)\s([^\s]+)\s\-\s[^\/]+\/([^\s]+)\s[^\s]+\s\\\"([^\"]+)\\\" \\\"([^\"]+)\\\" \\\"([^\"]+)\\\"/ ) {
  $timestamp_central=$1; $proxy_hostname_ip=$2; $client_hostname_ip=$3; $proxy_http_reply_code=$4; $timestamp_unix=$5; $client_http_method=$6; $client_http_uri=$7; $web_hostname_ip=$8; $client_http_useragent=$9; $client_http_referer=$10; $client_http_cookie=$11;
  $client_username="";
  print "passage dans seconde regexp.\n" if $debug2;
 }

# Default and Custom Apache log:
#<179>Jan 11 22:27:22 hostname programname: 1.1.1.1 - - [11/Jan/2013:22:27:16 +0100] \"GET /index.html HTTP/1.1\" 200 426 \"-\" \"Mozilla/5.0 (X11; Linux i686 on x86_64; rv:18.0) Gecko/20100101 Firefox/18.0\"
#<179>Jan 11 22:45:23 hostname programname: 1.1.1.1 - - [11/Jan/2013:22:45:14 +0100] \"GET /hourly.png HTTP/1.1\" 200 11363 \"http://1.1.1.111/abc.html\" \"Mozilla/5.0 (X11; Linux i686 on x86_64; rv:18.0) Gecko/20100101 Firefox/18.0\"
#<179>Jan 11 23:01:49 hostname programname: 1.1.1.1 - - [11/Jan/2013:23:01:42 +0100] \"GET /abc.exe HTTP/1.1\" 404 230 \"-\" \"Mozilla/5.0 (X11; Linux i686 on x86_64; rv:18.0) Gecko/20100101 Firefox/18.0\"
#<179>Jan 12 11:24:25 hostname programname: 1.1.1.1 - - [12/Jan/2013:11:24:17 +0100] \"GET /home_all.png HTTP/1.1\" 304 - \"http://1.1.1.111/abc.pl\" \"Mozilla/5.0 (X11; Linux i686 on x86_64; rv:18.0) Gecko/20100101 Firefox/18.0\"
#2013-11-26T22:39:16.387745+01:00 hostname programname: 142.4.198.179 - - [26/Nov/2013:22:39:07 +0100] "GET /muieblackcat HTTP/1.1" 404 218
# add referer + user-agent + cookie :
# 2013-11-22T22:01:49.577030+01:00 hostname programname: 1.1.1.11 - - [22/Nov/2013:22:01:48 +0100] "GET / HTTP/1.1" 200 1564 "-" "Wget/1.13.4 (linux-gnu)" "fGGhTasdas=http"

# elsif ( $output_escape =~ /^(?:\<\d+\>)?(\S+\s+\d+\s+\d+\:\d+\:\d+|\d+\-\d+\-\d+T\d+\:\d+\:\d+(?:\.\d+)?[\-\+]\d+\:\d+)\s(\S+)\s\S+\:\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+\-\s+\-\s+\[(.*?)\]\s+\\\"([^\s]+)\s([^\s]+)\s.*\\\"\s(\d+)\s(?:\d+|\-)(?:$|\s\\\"(.*?)\\\"\s\\\"(.*?)\\\"\s\\\"(.*?)\\\"$)/ ) {
 elsif ( $output_escape =~ /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+\-\s+\-\s+\[(.*?)\]\s+\\\"([^\s]+)\s([^\s]+)\s.*\\\"\s(\d+)\s(?:\d+|\-)(?:$|\s\\\"(.*?)\\\"\s\\\"(.*?)\\\"\s\\\"(.*?)\\\"$)/ ) {
  $timestamp_central=$2;
  $proxy_hostname_ip=$1;
  $client_hostname_ip=$1;
  $timestamp_unix=$2;
  $client_http_method=$3;
  $client_http_uri=$4;
  $proxy_http_reply_code=$5;
  $client_http_referer=$8;
  $client_http_useragent=$9;
  $client_http_cookie=$10;
  $client_username="";
  print "passage dans troisieme regexp.\n" if $debug2;
 }

# log proxy TMG/FOREFRONT:
# 10.0.0.1     DOMAINE\USERNAME     Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E)     2013-07-21      00:00:00        SERVERNAME      http://abc.com/abcd       -       10.0.0.2  8080    4493    625     291     http    GET     http://abc.com/def     Upstream	200
#10.0.0.1     anonymous       Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0) 2013-07-21      00:00:12        SERVERNAME      http://www.google.com/22	855560    www.google.com  10.0.0.2     8085    1       1112    4587    http    GET     http://www.google.com/ -	12209
#10.0.0.1      anonymous       Microsoft-CryptoAPI/6.1 2013-07-21      04:54:20        SERVERNAME      -       rapidssl-crl.geotrust.com       10.0.0.2     8085    1       180     4587    http	GET     http://rapidssl-crl.geotrust.com/crls/rapidssl.crl      -       12209
#10.0.0.1\tanonymous\tMozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)\t2013-07-21\t00:01:06\tSERVERNAME\t-\t-\t10.0.0.2\t443\t0\t0\t544\tSSL-tunnel\t-\tmail.google.com:443\tInet\t407
#10.0.0.1	DOMAINE\USERNAME	Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)	2013-06-21	00:00:13	SERVERNAME	-	-	10.0.0.2	8085	0	1695	1532	SSL-tunnel	-	www.marketscore.com:443	Upstream	0
#10.0.0.1	DOMAINE\USERNAME	Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)	2013-06-21	00:00:24	SERVERNAME	-	www.marketscore.com	10.0.0.2	443	31	938	448	SSL-tunnel	CONNECT	-	-	12210

 elsif ( $output_escape =~ /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:\t|\\t)+(\S+)(?:\t|\\t)+(.*?)(?:\t|\\t)+(\d{4}\-\d{2}\-\d{2})(?:\t|\\t)+(\d{2}\:\d{2}\:\d{2})(?:\t|\\t)+([0-9a-zA-Z\-\_]+)(?:\t|\\t)+(.*?)(?:\t|\\t)+(.*?)(?:\t|\\t)+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:\t|\\t)+\d+(?:\t|\\t)+\d+(?:\t|\\t)+\d+(?:\t|\\t)+\d+(?:\t|\\t)+.*?(?:\t|\\t)+([0-9a-zA-Z\-\_]+)(?:\t|\\t)+(.*?)(?:\t|\\t)+/) {
  $client_hostname_ip=$1; $client_username=$2; $client_http_useragent=$3; $timestamp_central=$4." ".$5; $proxy_hostname_ip=$6; $client_http_referer=$7; $client_http_method=$9; $client_http_uri=$10;
  # https/ssl-tunnel:
  if( $10 eq "-" && $8 ne "-" )
  {
   $client_http_uri=$8;
  }
  print "passage dans quatrieme regexp.\n" if $debug2;
 }

# log proxy BlueCoat:
# Fields: (syslog header)           date       time  time-taken c-ip cs-username cs-auth-group cs-categories sc-filter-result sc-status cs(Referer) s-action rs(Content-Type) cs-method cs-uri-scheme cs-host cs-uri-port cs-uri-path cs-uri-query cs(User-Agent) s-ip sc-bytes cs-bytes x-virus-id
# Jan 10 11:10:21 10.0.0.1/10.0.0.1 2013-10-10 11:10:21 68 10.0.0.2 - - \"bc_rules\" CATEGORY 304 http://referer.com TCP_HIT image/gif GET http www.test.com 80 /path.gif - \"Mozilla/4.0\" 10.0.0.3 370 665 -
# Oct 10 11:10:21 10.0.0.1/10.0.0.1 2013-10-10 11:10:22 135 10.0.0.2 user group \"none\" CATEGORY 200 http://referer.com TCP_CLIENT_REFRESH application/javascript GET http www.test.com 80 /path.js - \"Mozilla/4.0\" 10.0.0.3 22159 568 -
# Oct 10 11:10:21 10.0.0.1/10.0.0.1 2013-10-10 11:10:23 15 10.0.0.2 user group \"none\" CATEGORY 204 - TCP_NC_MISS text/html GET http www.test.com 80 /path ?arg=1 \"Mozilla/4.0\" 10.0.0.3 321 491 -
# Oct 10 11:10:21 10.0.0.1/10.0.0.1 2013-10-10 11:10:24 1 10.0.0.2 - - \"none\" CATEGORY 407 - TCP_DENIED - CONNECT tcp www.test.com 443 / - \"Mozilla/4.0\" 10.0.0.3 330 308 -

 elsif ( $output_escape =~ /^(?:[a-zA-Z]{3}\s+\d+\s+\d{2}\:\d{2}\:\d{2}\s(\S+)\s)(\d{4}\-\d{2}\-\d{2})\s(\d{2}\:\d{2}\:\d{2})\s\d+\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s(\S+)\s(?:\-|\S+)\s\\\"[^\"]*?\\\"\s\S+\s\d+\s(\S+)\s\S+\s\S+\s(\S+)\s(\S+)\s(\S+)\s\d+\s(\S+)\s(\S+)\s(?:\\\"([^\"]*?)\\\"|(\-))\s\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s\d+\s\d+\s\-$/ ) {
  $proxy_hostname_ip=$1; $timestamp_central=$2." ".$3; $client_hostname_ip=$4; $client_username=$5; $client_http_referer=$6; $client_http_method=$7; $client_http_uri=$8.":\/\/".$9.$10; $client_http_useragent=$12;
  if( $8 eq "tcp" ) { $client_http_uri=$9.$10 }
  unless( $12 ) { $client_http_useragent=$13 }
  if( $11 ne "-" ) { $client_http_uri=$8.":\/\/".$9.$10.$11 }
  print "passage dans cinquieme regexp.\n" if $debug2;
 }


 else {
  print "aucun parser ne correspond au motif !!! $output_escape\n";
 }

 
 print "timestamp_central: ",$timestamp_central if $timestamp_central && $debug2;
 print ", proxy_hostname_ip: ",$proxy_hostname_ip if $proxy_hostname_ip && $debug2;
 print ", timestamp_unix: ",$timestamp_unix if $timestamp_unix && $debug2;
 print ", client_hostname_ip: ",$client_hostname_ip if $client_hostname_ip && $debug2;
 print ", client_username: ",$client_username if $client_username && $debug2;
 print ", proxy_http_reply_code: ",$proxy_http_reply_code if $proxy_http_reply_code && $debug2;
 print ", client_http_method: ",$client_http_method if $client_http_method && $debug2;
 print ", client_http_uri: ",$client_http_uri if $client_http_uri && $debug2;
 print ", web_hostname_ip: ",$web_hostname_ip if $web_hostname_ip && $debug2;
 print ", client_http_useragent: ",$client_http_useragent if $client_http_useragent && $debug2;
 print ", client_http_referer: ",$client_http_referer if $client_http_referer && $debug2;
 print ", client_http_cookie: ",$client_http_cookie if $client_http_cookie && $debug2;
 print "\n" if $timestamp_central && $debug2;

####################################################################################################

 # de-encoded char :
 if( $client_http_uri )
 {
  my $countloop=0;
  #while( $client_http_uri =~ /\%/ )
  while( index($client_http_uri, '%') != -1 )
  {
   $countloop++;
   $client_http_uri=uri_unescape($client_http_uri);
   print "unescape: $client_http_uri\n" if $debug2;
   if( $countloop>4 ) { last }
  }
  $client_http_uri =~ s/\x00/\%00/g;
 }

####################################################################################################

 if( $client_http_uri )
 {
  my $etmsg;

  foreach $etmsg ( sort( keys %hash ) )
  {
   my $jump=0;
   my $founduricourt1=0;
   my $foundurilong1=0;
   my $foundagent=0;
   my $foundmethod=0;
   my $foundreferer=0;
   my $foundpcreuri=0;
   my $foundpcreagent=0;
   my $foundpcrecookie=0;

   foreach $clef ( sort( keys %{$hash{$etmsg}} ) )
   {
    print "hash2 etmsg: $etmsg, clef: $clef\n" if $debug2 && $_;

    if( $clef eq "httpmethod" && !$jump )
    {
     if( $hash{$etmsg}{"httpmethod"}[1] eq "nocase" && $client_http_method && index(lc($client_http_method), lc($hash{$etmsg}{"httpmethod"}[0])) != -1 )
     {
      print "ici1a: ",$hash{$etmsg}{"httpmethod"}[0],"\n" if $debug2 && $hash{$etmsg}{"httpmethod"}[0];
      $foundmethod=1;
     }
     elsif( $hash{$etmsg}{"httpmethod"}[0] && $client_http_method && index($client_http_method, $hash{$etmsg}{"httpmethod"}[0]) != -1 )
     {
      print "ici1b: ",$hash{$etmsg}{"httpmethod"}[0],"\n" if $debug2 && $hash{$etmsg}{"httpmethod"}[0];
      $foundmethod=1;
     }
     elsif( $hash{$etmsg}{"httpmethod"}[0] )
     {
      print "method not found: jump (",$hash{$etmsg}{"httpmethod"}[0],")\n" if $debug2;
      $jump=1;
      last;
     }
    }

    elsif( $clef eq "httpuricourt" && !$jump )
    {
     if( $hash{$etmsg}{"httpuricourt"}[0] && $client_http_uri && index(lc($client_http_uri), lc($hash{$etmsg}{"httpuricourt"}[0])) != -1 )
     {
      print "ici2: ",$hash{$etmsg}{"httpuricourt"}[0],"\n" if $debug2 && $hash{$etmsg}{"httpuricourt"}[0];
      $founduricourt1=1;
     }
     elsif( $hash{$etmsg}{"httpuricourt"}[0] )
     {
      print "uri not found: jump (",$hash{$etmsg}{"httpuricourt"}[0],")\n" if $debug2;
      $jump=1;
      last;
     }
    }

    elsif( $clef eq "httpurilong" && !$jump )
    {
     my $hashindexhttpurilong=0;
     foreach ( @{$hash{$etmsg}{"httpurilong"}} )
     {
      if( $hash{$etmsg}{"httpurilong"}[$hashindexhttpurilong] && $client_http_uri && index(lc($client_http_uri), lc($hash{$etmsg}{"httpurilong"}[$hashindexhttpurilong])) != -1 )
      {
       print "ici3: ",$hash{$etmsg}{"httpurilong"}[$hashindexhttpurilong],"\n" if $debug2 && $hash{$etmsg}{"httpurilong"}[$hashindexhttpurilong];
       $foundurilong1=1;
      }
      elsif( $hash{$etmsg}{"httpurilong"}[$hashindexhttpurilong] )
      {
       print "uri not found: jump (",$hash{$etmsg}{"httpurilong"}[$hashindexhttpurilong],")\n" if $debug2;
       $jump=1;
       $foundurilong1=0;
       last;
      }
      $hashindexhttpurilong++;
     }
    }

    elsif( $clef eq "httpagentshort" && !$jump )
    {
     if( $hash{$etmsg}{"httpagentshort"}[0] && $client_http_useragent && index(lc($client_http_useragent), lc($hash{$etmsg}{"httpagentshort"}[0])) != -1 )
     {
      print "ici4: ",$hash{$etmsg}{"httpagentshort"}[0],"\n" if $debug2 && $hash{$etmsg}{"httpagentshort"}[0];
      $foundagent=1;
     }
     elsif( $hash{$etmsg}{"httpagentshort"}[0] )
     {
      print "agent not found: jump (",$hash{$etmsg}{"httpagentshort"}[0],")\n" if $debug2;
      $jump=1;
      last;
     }
    }

    elsif( $clef eq "pcrereferer" && !$jump )
    {
     if( $hash{$etmsg}{"pcrereferer"}[0] && $client_http_referer && $client_http_referer =~ /$hash{$etmsg}{"pcrereferer"}[0]/i )
     {
      print "ici5: ",$hash{$etmsg}{"pcrereferer"}[0]," \n" if $debug2 && $hash{$etmsg}{"pcrereferer"}[0];
      $foundreferer=1;
     }
     elsif( $hash{$etmsg}{"pcrereferer"}[0] )
     {
      print "pcrereferer not found: jump (",$hash{$etmsg}{"pcrereferer"}[0],")\n" if $debug2;
      $jump=1;
      last;
     }
    }

    elsif( $clef eq "pcreagent" && !$jump )
    {
     if( $hash{$etmsg}{"pcreagent"}[1] && $client_http_useragent && $client_http_useragent =~ /$hash{$etmsg}{"pcreagent"}[0]/i )
     {
      print "ici6a: ",$hash{$etmsg}{"pcreagent"}[0],"\n" if $debug2 && $hash{$etmsg}{"pcreagent"}[0];
      $foundpcreagent=1;
     }
     elsif( !$hash{$etmsg}{"pcreagent"}[1] && $client_http_useragent && $client_http_useragent =~ /$hash{$etmsg}{"pcreagent"}[0]/ )
     {
      print "ici6b: ",$hash{$etmsg}{"pcreagent"}[0],"\n" if $debug2 && $hash{$etmsg}{"pcreagent"}[0];
      $foundpcreagent=1;
     }
     elsif( $hash{$etmsg}{"pcreagent"}[0] )
     {
      print "pcreagent not found: jump (",$hash{$etmsg}{"pcreagent"}[0],")\n" if $debug2;
      $jump=1;
      last;
     }
    }

    elsif( $clef eq "pcrecookie" && !$jump )
    {
     if( $hash{$etmsg}{"pcrecookie"}[1] && $client_http_cookie && $client_http_cookie =~ /$hash{$etmsg}{"pcrecookie"}[0]/i )
     {
      print "ici7a: ",$hash{$etmsg}{"pcrecookie"}[0],"\n" if $debug2 && $hash{$etmsg}{"pcrecookie"}[0];
      $foundpcrecookie=1;
     }
     elsif( !$hash{$etmsg}{"pcrecookie"}[1] && $client_http_cookie && $client_http_cookie =~ /$hash{$etmsg}{"pcrecookie"}[0]/ )
     {
      print "ici7b: ",$hash{$etmsg}{"pcrecookie"}[0],"\n" if $debug2 && $hash{$etmsg}{"pcrecookie"}[0];
      $foundpcrecookie=1;
     }
     elsif( $hash{$etmsg}{"pcrecookie"}[0] )
     {
      print "pcrecookie not found: jump (",$hash{$etmsg}{"pcrecookie"}[0],")\n" if $debug2;
      $jump=1;
      last;
     }
    }

    elsif( $clef eq "pcreuri" && !$jump )
    {
     if( $hash{$etmsg}{"pcreuri"}[1] && $client_http_uri && $client_http_uri =~ /$hash{$etmsg}{"pcreuri"}[0]/i )
     {
      print "ici8a: ",$hash{$etmsg}{"pcreuri"}[0],"\n" if $debug2 && $hash{$etmsg}{"pcreuri"}[0];
      $foundpcreuri=1;
     }
     elsif( !$hash{$etmsg}{"pcreuri"}[1] && $client_http_uri && $client_http_uri =~ /$hash{$etmsg}{"pcreuri"}[0]/ )
     {
      print "ici8b: ",$hash{$etmsg}{"pcreuri"}[0],"\n" if $debug2 && $hash{$etmsg}{"pcreuri"}[0];
      $foundpcreuri=1;
     }
     elsif( $hash{$etmsg}{"pcreuri"}[0] )
     {
      print "pcreuri not found: jump (",$hash{$etmsg}{"pcreuri"}[0],")\n" if $debug2;
      $jump=1;
      last;
     }
    }
   }
   unless( $jump )
   {
    if( $syslogsock && ($foundmethod or $founduricourt1 or $foundurilong1 or $foundagent or $foundreferer or $foundpcreagent or $foundpcrecookie or $foundpcreuri) )
    {
     print $syslogsock "ok trouver: ";
     print $syslogsock "timestamp: $timestamp_central, " if $timestamp_central;
     print $syslogsock "proxy_hostname_ip: $proxy_hostname_ip, " if $proxy_hostname_ip;
     print $syslogsock "client_hostname_ip: $client_hostname_ip, " if $client_hostname_ip;
     print $syslogsock "client_username: $client_username, " if $client_username;
     print $syslogsock "client_http_method: $client_http_method, " if $client_http_method;
     print $syslogsock "client_http_uri: $client_http_uri, " if $client_http_uri;
     print $syslogsock "client_http_useragent: $client_http_useragent, " if $client_http_useragent;
     print $syslogsock "client_http_referer: $client_http_referer, " if $client_http_referer;
     print $syslogsock "client_http_cookie: $client_http_cookie, " if $client_http_cookie;
     print $syslogsock "etmsg: $etmsg" if $etmsg;
     print $syslogsock ", etmethod: ",$hash{$etmsg}{"httpmethod"}[0] if $foundmethod;
     print $syslogsock ", eturishort: ",$hash{$etmsg}{"httpuricourt"}[0] if $founduricourt1;
     print $syslogsock ", eturilong: ",$hash{$etmsg}{"httpurilong"}[0] if $foundurilong1;
     print $syslogsock ", etagent: ",$hash{$etmsg}{"httpagentshort"}[0] if $foundagent;
     print $syslogsock ", etpcrereferer: ",$hash{$etmsg}{"pcrereferer"}[0] if $foundreferer;
     print $syslogsock ", etpcreagent: ",$hash{$etmsg}{"pcreagent"}[0] if $foundpcreagent;
     print $syslogsock ", etpcrecookie: ",$hash{$etmsg}{"pcrecookie"}[0] if $foundpcrecookie;
     print $syslogsock ", etpcreuri: ",$hash{$etmsg}{"pcreuri"}[0] if $foundpcreuri;
     print $syslogsock "\n";
    }
    elsif( $foundmethod or $founduricourt1 or $foundurilong1 or $foundagent or $foundreferer or $foundpcreagent or $foundpcrecookie or $foundpcreuri )
    {
     print "ok trouver: ";
     print "timestamp: $timestamp_central, " if $timestamp_central;
     print "proxy_hostname_ip: $proxy_hostname_ip, " if $proxy_hostname_ip;
     print "client_hostname_ip: $client_hostname_ip, " if $client_hostname_ip;
     print "client_username: $client_username, " if $client_username;
     print "client_http_method: $client_http_method, " if $client_http_method;
     print "client_http_uri: $client_http_uri, " if $client_http_uri;
     print "client_http_useragent: $client_http_useragent, " if $client_http_useragent;
     print "client_http_referer: $client_http_referer, " if $client_http_referer;
     print "client_http_cookie: $client_http_cookie, " if $client_http_cookie;
     print "etmsg: $etmsg" if $etmsg;
     print ", etmethod: ",$hash{$etmsg}{"httpmethod"}[0] if $foundmethod;
     print ", eturishort: ",$hash{$etmsg}{"httpuricourt"}[0] if $founduricourt1;
     print ", eturilong: ",$hash{$etmsg}{"httpurilong"}[0] if $foundurilong1;
     print ", etagent: ",$hash{$etmsg}{"httpagentshort"}[0] if $foundagent;
     print ", etpcrereferer: ",$hash{$etmsg}{"pcrereferer"}[0] if $foundreferer;
     print ", etpcreagent: ",$hash{$etmsg}{"pcreagent"}[0] if $foundpcreagent;
     print ", etpcrecookie: ",$hash{$etmsg}{"pcrecookie"}[0] if $foundpcrecookie;
     print ", etpcreuri: ",$hash{$etmsg}{"pcreuri"}[0] if $foundpcreuri;
     print "\n";
    }
   }
  }
 }

#    $i1=0; $uriexist1=0; $uriexist2=0; $founduricourt1=0; $foundurilong1=0; $founduri2=0; $agentexist=0; $foundagent=0; $methodexist=0; $foundmethod=0; $refererexist=0; $foundreferer=0;
 $timestamp_central=0; $proxy_hostname_ip=0; $timestamp_unix=0; $client_hostname_ip=0; $client_username=0; $proxy_http_reply_code=0; $client_http_method=0; $client_http_uri=0; $web_hostname_ip=0; $client_http_useragent=0; $client_http_referer=0; $client_http_cookie=0;

  }
 }
), 1..$max_procs;

# Send work to the thread
$queue->enqueue($_) while( <STDIN> );

$queue->enqueue( (undef) x $max_procs );

# terminate.
$_->join() for @threads;

close FILEEMERGINGTHREATS;
exit(0);

