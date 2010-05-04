#!/usr/bin/perl
use strict;
use LWP::UserAgent;
use Compress::Raw::Zlib ;

sub cat
{
        my $filename = shift;;
        my $contents;
        my $line;
        open FILE, "< $filename";
        while ($line = <FILE>) {
                $contents .= $line;
        }
        close FILE;
        return $contents;
}

my $ua = LWP::UserAgent->new;

my $xml;
my $ver = $ARGV[0];#'3.0144'; #'2.0400';
my $mac = $ARGV[1];
if ( ! defined $ver) {
	die "usage: eyefi-firmware-fetch.pl <FIRMWARE VERSION> [optional MAC]";
}
while (1) {
	my $m1 = 0x2d; #rand 0x30;
	my $m2 = rand 256;
	my $m3 = rand 256;
	if (! length($mac)) {
		$mac = sprintf '00-18-56-%02x-%02x-%02x', $m1, $m2, $m3;
	}
	my $url = sprintf 'http://api.eye.fi/api/rest/eyeserver/v1/getCardFirmware?Card=%s&Version=%s', $mac, $ver;
	print $url."\n";
	my $res = $ua->get($url);
	$xml = $res->content();
	#rint $xml."\n";
	next if $xml =~ /Card not found./;
	next if $xml =~ /File not found./;
	last;
}
my $filename .= "EYEFIFWU-$ver-$mac.bin";
printf STDERR "got %d bytes of xml\n", length($xml);
#strip the XML off:
$xml =~ s/<\?xml.*<Firmware>//s;
printf STDERR "got %d bytes of xml\n", length($xml);
$xml =~ s/<\/Firmware>.*Response>//s;
printf STDERR "got %d bytes of xml\n", length($xml);
my $base64_encoded = $xml;
printf STDERR "got %d bytes of base64 encoded data\n", length($base64_encoded);

use Email::MIME::Encodings;
my $zlib_encoded = Email::MIME::Encodings::decode(base64 => $base64_encoded);

printf STDERR "got %d bytes of zlib encoded data\n", length($zlib_encoded);

my $status;
my $output;

my $i;
($i, $status) = new Compress::Raw::Zlib::Inflate() ;
$status = $i->inflate($zlib_encoded, $output);
$status = $i->inflateSync($zlib_encoded);

open FILE, "> $filename";
print FILE $output;
close FILE;
printf STDERR "done, wrote %d bytes to '$filename'\n", length($output);
