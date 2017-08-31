# DShield PFSense Client
Convert pfsense firewall logs into dshield format for ingesting them into the dshield project

This script *should* work in pfsense 2.2 and 2.3 but only has been tested currently with the most recent version (2.3.4-RELEASE-p1). It does **NEED** email configured on the pfsense notification setup. To adjust it, see System->Advanced->Notifications and the e-mail section.

## Get the log converter script
Place this PHP script in a convenient location ie: `/root/bin/dshieldpfsense.php`

1. You can copy & paste the contents of the php script if you have an SSH session on your pfsesne box.
2. Another approach would be to scp the file to the server. If you want to use scp, remember that you must scp as root and not admin.      The admin account does not have privileges to put files on the system.
3. You can curl the script onto the pfsense box.
  - ```curl https://raw.githubusercontent.com/jullrich/dshieldpfsense/master/dshield.php > /root/bin/dshieldpfsense.php```

## Editing necessary variables
Before running it, modify the file to add the email address and the API key for your DShield account. You can find the API key here: https://www.dshield.org/myaccount.html

```
$authkey='--- insert authkey here. see dhsield.org/myaccount.html ---';
$fromaddr='--- your from address. this is where bounces will go ---';
$uid='--- your numeric userid see dshield.org/myaccount.html ---';
```
<p align="left">
<img src="https://github.com/funtimes-ninja/dshieldpfsense/raw/master/images/dshield-acct.png" width="350"/>
</p>

## Common interface issue
Ensure the variable for ```$interfaces=array('WAN');``` is set properly!
You need to know the alias name of your WAN interface. This can viewed at https://<pfsense.ip>/status_interfaces.php

<p align="left">
  <img src="https://github.com/funtimes-ninja/dshieldpfsense/raw/master/images/interface.png" width="350"/>
</p>

## Ensure the script is executable
```
chmod 770 /root/bin/dshieldpfsense.php/
```
## Place script in crontab
```
11,41 * * * * /root/bin/dshieldpfsense.php
```

## Debugging
You will see messages left by the script in the system.log. To review, use:

```
clog /var/log/system.log | grep dshield
```

You can also change the "toaddr" in the script to temporarily send logs to a different address.

The last log sent can also be found in /tmp/lastdshiedllog

Each time the script runs, it will update /var/run/dshieldlastts with the timestamp of the last log line processed.

Please report errors or request enhancements via a bug report here.
