#!/usr/local/bin/php -q
<?php

/**
 *   DShield PFSense Client Version 0.000006
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

$version='0.000006';

# include some standard libraries
require_once("globals.inc");
require_once("functions.inc");
require_once("filter.inc"); // In pfSense 2.5, filter_log.inc was renamed to filter.inc


$dshield_config=parse_ini_file("dshield.ini",true);
$dshield_config=$dshield_config['dshield'];


# for debugging, change the 'To' address or add a second address
$toaddr='reports@dshield.org';

$debug=(int)($dshield_config['debug']);
$interfaces=explode(',',$dshield_config['interfaces']);
$authorized_source_ip=explode(',',$dshield_config['authorized_source_ip']);

if ( $dshield_config['apikey'] == '' ) {
  print "An API Key is required. Check dshield.ini\n";
  exit();
}else{
  $apikey=$dshield_config['apikey'];
}

if ($dshield_config['fromaddr'] == '' ) {
  $from = $config['notifications']['smtp']['fromaddress'];
} else {
  $from = $dshield_config['fromaddr'];
}
if ( $from == '' ) {
  print "A 'From Address' is required. Check dshield.ini\n";
  exit();
}

# some older versions used userid instead of uid. allowing for both.
if ( $dshield_config['uid'] == '' && $dshield_config['userid'] == '' ) {
  print "A DShield UID is required. Check dshield.ini\n";
  exit();
} else {
  if ( $dshield_config['uid'] == '' )  {
    $uid=$dshield_config['userid'];
  } else {
    $uid = $dshield_config['uid'];
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
if (!isset($config['notifications']['smtp']['ipaddress'])) {
	print "No SMTP server is defined under Systems->Advanced->Notifications\n";
	exit();
}

$src_exc_lo = array();
$src_exc_hi = array();
if ($dshield_config['source_exclude']) {
  load_excludes($dshield_config['source_exclude'], $src_exc_lo, $src_exc_hi, True);
}
$tgt_exc_lo = array();
$tgt_exc_hi = array();
if ($dshield_config['target_exclude']) {
  load_excludes($dshield_config['target_exclude'], $tgt_exc_lo, $tgt_exc_hi, True);
}
$src_port_exc_lo = array();
$src_port_exc_hi = array();
if ($dshield_config['source_port_exclude']) {
  load_excludes($dshield_config['source_port_exclude'], $src_port_exc_lo, $src_port_exc_hi, False);
}
$tgt_port_exc_lo = array();
$tgt_port_exc_hi = array();
if ($dshield_config['target_port_exclude']) {
  load_excludes($dshield_config['target_port_exclude'], $tgt_port_exc_lo, $tgt_port_exc_hi, False);
}


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
# handle failures to parse log line.
    if ($flent == "") {
        if ($debug===1) {
            print "failed to parse line ($line)\n";
        }
        continue;
    }

# eliminating ICMP (we don't log that) and TCP with FA and RA flags as these are usually false positives, as well as A and R
# do not send self blocked lines nor IPV6
	
    if ($flent != "" && $flent['version'] == '4' && in_array($flent['srcip'],$authorized_source_ip) == false && in_array($flent['interface'],$interfaces) && $flent['proto']!='ICMP' && $flent['tcpflags']!='FA' && $flent['tcpflags']!='RA'  && $flent['tcpflags'] != 'SA' && $flent['tcpflags']!='A'  && $flent['tcpflags']!='R' ) {
        $time=strtotime($flent['time']);

# check if this log line is newer then the last one we processesed.
        if ( $time>$lasttime) {
            if (test_IP_exclude($src_exc_lo, $src_exc_hi, $flent['srcip'])) {
              if ($debug === 1) {
                print $flent['srcip'] . " is in a source ip exclusion block.\n";
              }
              continue;
            }
            if (test_IP_exclude($tgt_exc_lo, $tgt_exc_hi, $flent['dstip'])) {
              if ($debug === 1) {
                print $flent['dstip'] . " is in a target ip exclusion block.\n";
              }
              continue;
            }
            if (test_port_exclude($src_port_exc_lo, $src_port_exc_hi, $flent['srcport'])) {
              if ($debug === 1) {
                print $flent['srcport'] . " is in a source port exclusion block.\n";
              }
              continue;
            }
            if (test_port_exclude($tgt_port_exc_lo, $tgt_port_exc_hi, $flent['dstport'])) {
              if ($debug === 1) {
                print $flent['dstport'] . " is in a target port exclusion block.\n";
              }
              continue;
            }
            $linesout.=date("Y-m-d H:i:s P",$time)."\t{$dshield_config['uid']}\t1\t{$flent['srcip']}\t{$flent['srcport']}\t{$flent['dstip']}\t{$flent['dstport']}\t{$flent['proto']}\t{$flent['tcpflags']}\n";
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

if ( $dshield_config['ccaddr'] !== '' ) {
 	$toaddr = $toaddr ."," .$dshield_config['ccaddr'];
 }

	$headers = array(
		"From"    => $from,
		"To"      => $toaddr,
		"Subject" => $sSubject,
		"Date"    => date("r")
	);

file_put_contents("/tmp/lastdshieldlog",$linesout);


if ( $config['version']>=16 ) {
		//pfsense 2.4
		send_smtp_message_24();
}else{
		//pfsense 2.3 and below
		send_smtp_message_23();
}
##### fork from /etc/inc/notices.inc		
function send_smtp_message_24() {
	global $config, $g, $from, $toaddr, $headers, $linesout, $linecnt ;
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
	} else {
		log_error(sprintf(gettext("%d lines sent to DShield OK"), $linecnt));
		print "send $linecnt lines to DShield OK\n";
		return;
	}

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


function load_excludes($exc_file, &$arr_lo, &$arr_hi, $is_ip) {
  global $debug;
  if (!file_exists($exc_file)) {
    log_error(sprintf(gettext("Exclude file '%s' does not exist."), $exc_file));
    exit();
  }

  if ($debug===1) {
      print "load_excludes: reading excludes from $exc_file.\n";
  }

  $fh = fopen($exc_file,"r");
  if ($fh) {
    while (($line = fgets($fh)) !== false) {
      $line = trim($line);
      if (preg_match("/^\s*#/", $line) || preg_match("/^\s*$/", $line)) {
        continue;
      }
      if ($debug===1) {
        print "load_excludes:   line=>>$line<<\n";
      }
      # 127.0.0.0/8 format
      if (strstr($line, "/")) {
        $parts = explode("/", $line);
        $lo = $parts[0];

        # nb: the following code block is from https://www.php.net/manual/en/ref.network.php
        $lo_bin = str_pad(decbin(ip2long($lo)), 32, "0", STR_PAD_LEFT);
        $netmask_bin = str_pad(str_repeat("1", (integer)$parts[1]), 32, "0", STR_PAD_RIGHT);

        $hi_bin = ""; 
        for ($i = 0; $i < 32; $i++) {
          if ($netmask_bin[$i] == "1")
            $hi_bin .= $lo_bin[$i];
          else
            $hi_bin .= "1";
        }
        $hi = long2ip(bindec($hi_bin));
      } else {
      # 127.0.0.0 - 127.255.255.255 format
        $parts = explode("-", $line);
        $lo = trim($parts[0]);
        if (count($parts) === 1) {
          $hi = $lo;
        } else {
          $hi = trim($parts[1]);
        }
      }
      if ($debug===1) {
        print "load_excludes:     lo=>>$lo<<; hi=>>$hi<<\n";
      }
      if ($is_ip) {
        if (filter_var($lo, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && filter_var($hi, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
          $arr_lo[] = $lo;
          $arr_hi[] = $hi;
        } else {
          if ($lo != $hi && !filter_var($lo, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && !filter_var($hi, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            log_error(sprintf(gettext("%d and %d are not valid IPv4 addresses!"), $lo, $hi));
          } else {
            if (!filter_var($lo, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
              log_error(sprintf(gettext("%d is not a valid IPv4 address!"), $lo));
            } else {
              log_error(sprintf(gettext("%d is not a valid IPv4 address!"), $hi));
            }
          }
        }
      } else {
        if ((int)($lo) > 0 && (int)($lo) <= 65535 && (int)($hi) > 0 && (int)($hi) <= 65535) {
          $arr_lo[] = $lo;
          $arr_hi[] = $hi;
        } else {
          if ($lo != $hi && !((int)($lo) > 0 && (int)($lo) <= 65535 && (int)($hi) > 0 && (int)($hi) <= 65535)) {
            log_error(sprintf(gettext("%d and %d are not valid port numbers!"), $lo, $hi));
          } else {
            if ((int)($lo) <= 0 || (int)($lo) > 65535) {
              log_error(sprintf(gettext("%d is not a valid port number!"), $lo));
            } else {
              log_error(sprintf(gettext("%d is not a valid port number!"), $hi));
            }
          }
        }
      }
    }

    fclose($fh);
  } else {
    log_error(sprintf(gettext("Failed to read exclude file '%s'!"), $exc_file));
    exit();
  } 
}

function test_IP_exclude($arr_lo, $arr_hi, $ip) {
  global $debug;
  if ($debug === 1) {
    print "test_IP_exclude: checking $ip.\n";
  }
  $n = count($arr_lo);
  for ($i=0; $i<$n; $i++) {
    if ($debug === 1) {
      print "test_IP_exclude:  against range " . $arr_lo[$i] . " - " . $arr_hi[$i] . ".\n";
    }
    $l = ip2long($ip);
    if ($l >= ip2long($arr_lo[$i]) && $l <= ip2long($arr_hi[$i]))
    {
      return True;
    }
  }
  return False;
}

function test_port_exclude($arr_lo, $arr_hi, $port) {
  global $debug;
  if ($debug === 1) {
    print "test_port_exclude: checking $port.\n";
  }
  $n = count($arr_lo);
  for ($i=0; $i<$n; $i++) {
    if ($debug === 1) {
      print "test_port_exclude:  against range " . $arr_lo[$i] . " - " . $arr_hi[$i] . ".\n";
    }
    if ((int)($port) >= (int)($arr_lo[$i]) && (int)($port) <= (int)($arr_hi[$i]))
    {
      return True;
    }
  }
  return False;
}


?>
