# DShield PFSense Client
Place this PHP script in a convinient location (I use "/root/bin/" and add a cron job to run it twice an hour.

Before running it, modify the file to add the e-mail address and the API key for your DShield account. You can find the API key here: https://www.dshield.org/myaccount.html

This script *should* work in pfsense 2.2 and 2.3 but only has been tested currently with the most recent version (2.3.4-RELEASE-p1). It does rely on the pfsense notification setup. To adjust it, see System->Advanced->Notifications and the e-mail section.

For debugging: you will see messages left by the script in the system.log. To review, use:

```
clog /var/log/system.log | grep dshield
```

You can also change the "toaddr" in the script to temporarily send logs to a different address.

The last log sent can also be found in /tmp/lastdshiedllog

Each time the script runs, it will update /var/run/dshieldlastts with the timestamp of the last log line processed.

Pleae report errors or request enhancements via a bug report here.


