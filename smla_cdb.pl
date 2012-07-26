#!/usr/bin/perl

# SendMail Log Analyzer
# by Troex Nevelin (ver 0.2)

# Changes:
#	* DB -> in-memory hash, than CDB (faster)
#	* GZip read
#	* unstricted :(

#use strict;
use Digest::MD5;
use CDB_File;
use Compress::Zlib;

# CONFIG START
my $statpath = "/var/www/htdocs/mail/mr.smla";
my %logs = (
#	"/var/log/maillog.7.gz" => "static",
#	"/var/log/maillog.6.gz" => "static",
#	"/var/log/maillog.5.gz" => "static",
#	"/var/log/maillog.4.gz" => "static",
#	"/var/log/maillog.3.gz" => "static",
#	"/var/log/maillog.2.gz" => "static",
#	"/var/log/maillog.1.gz" => "static",
	"/var/log/maillog.0.gz" => "static",
	"/var/log/maillog" => "current"
);
# CONFIG END

# (better) do net edit below

my $i = 0;
my $mindate = 0;
my $maxdate = 0;

my %stat = ();
my %sendmail = ();
my %sendmail_meta = ();


$| = 1;

foreach my $logfile (sort { $b cmp $a } keys %logs) {
	print "* $logfile [$logs{$logfile}]";
	my ($meta, $nlogfile);
	my @FILES = ();
	
	$nlogfile = $statpath."/logs/";
	
	if ($logs{$logfile} eq "static") {
		open(LOG, "< $logfile") or die "Can't open $logfile: $!\n";
		binmode(LOG);
		my $md5 = Digest::MD5->new->addfile(*LOG)->hexdigest;
		close(LOG);
		print " md5(".$md5.")\n";
		$nlogfile .= $md5;
		$meta = $md5;
		my @FILES = glob($nlogfile.'_*-*');
		if (@FILES > 0) {
			next;
		}
	} elsif ($logs{$logfile} eq "current") {
		print "\n";
		$nlogfile .= "current";
		$meta = "current";
		@FILES = glob($nlogfile.'_*-*');
		if (@FILES > 0) {
			for (@FILES) {
				unlink($_) or print "Can't remove $_: $!\n";
			}
		}
		@FILES = glob($statpath.'/meta/'.$meta.'_*-*');
		if (@FILES > 0) {
			for (@FILES) {
				unlink($_) or print "Can't remove $_: $!\n";
			}
		}

	}
	
	
	@T = localtime(time);
	$y = $T[5]+1900;
	$mindate = 0;
	$maxdate = 0;

	%stat = ();
	%sendmail = ();
	%sendmail_meta = ();

	my $slogfile = $statpath."/logs/".$meta;
	my $metafile = $statpath."/meta/".$meta;


	print "\twriting raw log/meta database...";

	if ($logfile =~ /\.gz$/) {
		my $gz = gzopen($logfile, "rb") or die "Cannot open $logfile: $gzerrno\n";
		while ($gz->gzreadline($_) > 0) {
			&analyze($_)
		}
	} else {
		open(LOG, "< $logfile");
		while(<LOG>) {
			&analyze($_);
		}
		close(LOG)
	}


	CDB_File::create %sendmail, $slogfile, "$slogfile.$$" or die "$0: can't create cdb: $!\n";
	CDB_File::create %sendmail_meta, $metafile, "$slogfile.$$" or die "$0: can't create cdb: $!\n";

	print " done\n";

	print "\tmindate: $mindate\n\tmaxdate: $maxdate\n";
	print "\tlog stats:";
	foreach my $k (keys %stat) {
		print " $k = $stat{$k};";
	}
	print "\n";

	rename($slogfile, $slogfile."_".$mindate."-".$maxdate.".cdb") or die "Can't rename $slogfile: $!\n";
	$slogfile .= "_".$mindate."-".$maxdate.".db";
	rename($metafile, $metafile."_".$mindate."-".$maxdate.".cdb") or die "Can't rename $metafile: $!\n";
	$metafile .= "_".$mindate."-".$maxdate.".db";
}

##### GZIP START
#
#print "\tcompressing $slogfile...";
#my $gz = gzopen($slogfile.".gz", "wb") or die "Cannot open gzip: $!\n";
#open(FILE, "< $slogfile") or die "Cannot open $slogfile: $!\n";
#while (<FILE>) {
#	$gz->gzwrite($_) or die "error writing: $!\n";
#}
#close(FILE);
#$gz->gzclose;
#print " done\n";
#
#print "\tdelete raw log..."; 
#unlink($slogfile) or die "Can't unlink $slogfile: $!\n";
#print " done\n";
#
##### GZIP END


sub analyze {	
	$_ = @_[0];
	$i++;
	if ($i >= 10000) {
		print ".";
		$i = 0;
	}
#	print;
	chomp;
	my $flog = $_;
	tr/ / /s;
	my ($m, $d, $t, $domain, $process, $log) = split(/ /, $_, 6);
	$process =~ s/(\[\d+\])|(\:$)//gx;
	$stat{$process} += 1;
	if ($process =~ /^(sendmail|sm-mta)$/) {
		my ($id, $log) = split(/ /, $log, 2);
		$id =~ s/\://;
		if ($id !~ /[\w\d]{8}\d{6}/) {
			#print "$id $log\n";
			next;
		}
		$sendmail{$id} .= "|".$flog;
		if (not($sendmail_meta{$id})) {
			$t =~ s/\://g;
			my $date	= $y.&month2num($m).&az($d).$t;
			$sendmail_meta{$id} .= $date;
			
			if ($maxdate == 0) { $maxdate = $date; }
			if ($mindate == 0) { $mindate = $date; }
			if ($maxdate < $date) { $maxdate = $date; }
			if ($mindate > $date) { $mindate = $date; }
		}
		if ($log =~ /^(from|to)\=/) {
			if ($log =~ /^((from|to)\=\<[\s\w\.\-\d\@\+\=]+\>)/) {
				$sendmail_meta{$id} .= "|".$1;
			} elsif ($log =~  /^((from|to)\=[\s\w\.\-\d\@\+\=\"\\\<\>]+)/) {
				$sendmail_meta{$id} .= "|".$1;
			}
	
		} elsif ($log =~ /^ruleset\=check_rcpt\,\s/) {
			$log =~ /arg1(\=\<[\s\w\.\-\d\@\+\=\"\\]+\>)/;
			$sendmail_meta{$id} .= "|to".$1;
			if ($log =~ /\sreject\=/) {
				$log =~ /\s(reject\=.+)$/;
				$sendmail_meta{$id} .= "|".$1;
			}
		} elsif ($log =~ /^lost\sinput\schannel/) {
			$sendmail_meta{$id} .= "|stat=".$log;
		} elsif ($log =~ /^rejecting\scommands/) {
			$sendmail_meta{$id} .= "|reject=".$log;
		}
		
		if ($log =~ /\sstat\=/) {
			$log =~ /\s(stat\=.+)$/;
			$sendmail_meta{$id} .= "|".$1;
		}	
	}
}

sub month2num {
	my $month = $_[0];
	$month = "\L".$month;
	$month = "\u".$month;
	my %m2n = (
		"Jan" => "01",
		"Feb" => "02",
		"Mar" => "03",
		"Apr" => "04",
		"May" => "05",
		"Jun" => "06",
		"Jul" => "07",
		"Aug" => "08",
		"Sep" => "09",
		"Oct" => "10",
		"Nov" => "11",
		"Dec" => "12"
	);
	my $num = $m2n{$month};
	if ($num =~ /^\d\d$/) {
		return $num;
	} else {
		return "00";
	}
}

sub az {
	my $i = shift;
	if ($i < 10) {
		$i = "0".$i;
	}
	return $i;
}
																
