#!/usr/local/bin/php -q
<?php

/**
 *   DShield PFSense Client Version 0.000004
 *	 https://github.com/jullrich/dshieldpfsense
 *
 *   for questions, please email jullrich - at - sans.edu
 *
 *  Install:
 *
 *   -  copy this file to a location where it is not in the way. E.g. /root/bin/dshield.php
 *   -  make the file executable chmod +x /root/bin/dshield.php
 *   -  create dshield.ini (see dshield.sample) in the same directory where you keep this file
 *   -  test run: /root/bin/dshield.php
 *   -  add to cron (crontab -e ... run twice an hour e.g. 11,41 * * * * /root/bin/dshield.php
 *
 *  In PFSense, you need to have a mail server configured for notifcations. See
 *    Systems->Advanced->Notifcations
 *
 */

$version='0.000004';

$config=parse_ini_file("dshield.ini",true);
$config=$config['dshield'];


# for debugging, change the 'To' address or add a second address
$toaddr='reports@dshield.org';

$debug=(int)($config['debug']);
$interfaces=split(',',$config['interfaces']);
$authorized_source_ip=split(',',$config['authorized_source_ip']);

if ( $config['apikey'] == '' ) {
  print "An API Key is required. Check dshield.ini\n";
  exit();
}else{
  $apikey=$config['apikey'];
}

if ( $config['fromaddr'] == '' ) {
  print "A 'From Address' is required. Check dshield.ini\n";
  exit();
}

if ($config['fromaddr'] == '' ) {
  $from = $config['notifications']['smtp']['fromaddress'];
} else {
  $from = $config['fromaddr'];
}
# some older versions used userid instead of uid. allowing for both.
if ( $config['uid'] == '' && $config['userid'] == '' ) {
  print "A DShield UID is required. Check dshield.ini\n";
  exit();
} else {
  if ( $config['uid'] == '' )  {
    $uid=$config['userid'];
  } else {
    $uid = $config['uid'];
  }
}

if ( $debug===1 ) {
    print "interactive/debug mode

   API Key: $apikey
      From: $from 
       UID: $uid 
Interfaces: ".join(',',$interfaces)."
";
}

if (isset($config['notifications']['smtp']['disable'])) {
	print "SMTP is disabled under Systems->Advanced->Notifcations\n";
	exit();
}
if (isset($config['notifications']['smtp']['ipaddress'])) {
	print "No smpt server is defined under Systems->Advanced->Notifications\n";
	exit();
}


# include some standard libraries
require_once("globals.inc");
require_once("sasl.inc");
require_once("smtp.inc");
require_once("functions.inc");
require_once("filter_log.inc");

# figure out local timezone
$sTZ=date('P');
# assemble subject line
$sSubject="FORMAT DSHIELD USERID $uid TZ $sTZ AUTHKEY $apikey PFSENSE $version";

# initialize variables
$linecnt=0;
$lasttime=0;

if ( $debug===1 ) {
    print "
Subject: $sSubject\n";
}

# check when we ran last.
if ( file_exists('/var/run/dshieldlastts') ) {
    $lasttime=file_get_contents('/var/run/dshieldlastts');
    if ( $debug === 1 ) {
        print "Last time script ran: $lasttime\n";
    }
} else {
    if ( $debug === 1 ) {
        print "could not find /var/run/dshieldlastts . Running for the first time?\n";
    }
}

# read the log
$log=fopen("/var/log/filter.log","r");
$linesout='';
while(!feof($log)) {
    $line = fgets($log);
    $line = rtrim($line);
    if ( $debug===1 ) {
        print "Reading $line\n";
    }
# the name of this function changed in Pfsense 2.3
    if ( $config['version']>=15 ) {
        $flent = parse_firewall_log_line(trim($line));
    } else {
        $flent = parse_filter_line(trim($line));
    }

# eliminating ICMP (we don't log that) and TCP with FA and RA flags as these are usually false positives, as well as A and R
# do not send self blocked lines nor IPV6
	
    if ($flent['version'] == '4' && in_array($flent['srcip'],$authorized_source_ip) == false && $flent != "" && in_array($flent['interface'],$interfaces) && $flent['proto']!='ICMP' && $flent['tcpflags']!='FA' && $flent['tcpflags']!='RA'  && $flent['tcpflags'] != 'SA' && $flent['tcpflags']!='A'  && $flent['tcpflags']!='R' ) {
        $time=strtotime($flent['time']);

# check if this log line is newer then the last one we processesed.
        if ( $time>$lasttime) {
            $linesout.=date("Y-m-d H:i:s P",$time)."\t{$config['uid']}\t1\t{$flent['srcip']}\t{$flent['srcport']}\t{$flent['dstip']}\t{$flent['dstport']}\t{$flent['proto']}\t{$flent['tcpflags']}\n";
            $flent='';
            $linecnt++;
        } else {
	    if ( $debug === 1 ) {
	      print "Log is too old $time vs $lastime\n";
            }
        }
    } else {
        if ( $debug === 1 ) {
        	print "Log was rejected due to wrong interface or flags or because it is ICMP or the IP version is not 4 or the source is our own IP address: protocol {$flent['proto']} interface {$flent['interface']} flags {$flent['tcpflags']} version {$flent['version']} source ip {$flent['srcip']}\n";
        } 
    }
}
fclose($log);

# done reading the log


# dealing with errors
if ( $lasttime>=$time ) {
    log_error("no new lines added to log since last run OK");
    exit();
}
if ( $linecnt==0 ){
    log_error("no new lines found to submit to dshield OK");
    exit();
}

# safe the "last run" time stamp for the next time we will run.

file_put_contents('/var/run/dshieldlastts',$time);

#
# sending log via email
#


	$headers = array(
		"From"    => $from,
		"To"      => $toaddr,
		"Subject" => $sSubject,
		"Date"    => date("r")
	);


if ( $config['ccaddr'] !='' ) {
    array_push($headers,'CC: '.$config['ccaddr']);
}

file_put_contents("/tmp/lastdshieldlog",$linesout);


if ( $config['version']>=16 ) {
		//pfsense 2.4
		if(send_smtp_message_24()) {
                log_error(sprintf(gettext("%d lines sent to DShield OK"), $linecnt));
		        print "send $linecnt lines to DShield OK\n";
		}
}else{
		//pfsense 2.3 and below
		send_smtp_message_23();
}
##### fork from /etc/inc/notices.inc		
function send_smtp_message_24() {
	global $config, $g, $from, $toaddr, $headers, $linesout ;
	require_once("Mail.php");


	if (empty($config['notifications']['smtp']['username']) ||
	    empty($config['notifications']['smtp']['password'])) {
		$auth = false;
		$username = '';
		$password = '';
	} else {
		$auth = isset($config['notifications']['smtp']['authentication_mechanism'])
		    ? $config['notifications']['smtp']['authentication_mechanism']
		    : 'PLAIN';
		$username = $config['notifications']['smtp']['username'];
		$password = $config['notifications']['smtp']['password'];
	}
	$params = array(
		'host' => (isset($config['notifications']['smtp']['ssl'])
		    ? 'ssl://'
		    : '')
		    . $config['notifications']['smtp']['ipaddress'],
		'port' => empty($config['notifications']['smtp']['port'])
		    ? 25
		    : $config['notifications']['smtp']['port'],
		'auth' => $auth,
		'username' => $username,
		'password' => $password,
		'localhost' => $config['system']['hostname'] . "." .
		    $config['system']['domain'],
		'timeout' => !empty($config['notifications']['smtp']['timeout'])
		    ? $config['notifications']['smtp']['timeout']
		    : 20,
		'debug' => false,
		'persist' => false
	);
	        
			if ( $debug === 1 ) {
        		print_r($headers);
				print_r($params);	
        } 
		
			   
	$smtp =& Mail::factory('smtp', $params);
	$mail = $smtp->send($toaddr, $headers, $linesout);
	if (PEAR::isError($mail)) {
		$err_msg = sprintf(gettext(
		    'Could not send the message to %1$s -- Error: %2$s'),
		    $toaddr, $mail->getMessage());
		print $err_msg;
		log_error($err_msg);
		return($err_msg);
	}

	return;

}


function send_smtp_message_23() {
	global $config, $g, $from, $toaddr, $headers, $linesout, $linecnt ;
	require_once("sasl.inc");
	require_once("smtp.inc");
	
	$smtp=new smtp_class;
	$smtp->host_name=$config['notifications']['smtp']['ipaddress'];
	$smtp->host_port = empty($config['notifications']['smtp']['port']) ? 25 : $config['notifications']['smtp']['port'];
	$smtp->direct_delivery = 0;
	$smtp->ssl = (isset($config['notifications']['smtp']['ssl'])) ? 1 : 0;
	$smtp->tls = (isset($config['notifications']['smtp']['tls'])) ? 1 : 0;
	$smtp->debug = 0;
	$smtp->html_debug = 0;
	$smtp->localhost=$config['system']['hostname'].".".$config['system']['domain'];
	if($config['notifications']['smtp']['username'] &&
		$config['notifications']['smtp']['password']) {
		if (isset($config['notifications']['smtp']['authentication_mechanism'])) {
			$smtp->authentication_mechanism = $config['notifications']['smtp']['authentication_mechanism'];
		} else {
			$smtp->authentication_mechanism = "PLAIN";
		}
		$smtp->user = $config['notifications']['smtp']['username'];
		$smtp->password = $config['notifications']['smtp']['password'];
	}
	
	if($smtp->SendMessage($from, $toaddr, $headers, $linesout)) {
		log_error(sprintf(gettext("%d lines sent to DShield OK"), $linecnt));
		print "send $linecnt lines to DShield OK\n";
	} else {
		log_error(sprintf(gettext('Could not send DShield logs to %1$s -- Error: %2$s'), $toaddr, $smtp->error));
		print "could not send $linecnt lines to DShield ERROR\n";
	}
}


?>
