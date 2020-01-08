# NGINX Log Parser
 A safe python NGINX log parser for Linux systems that generates email reports to a specified address. The reports include all NGINX access events in the file, broken into an HTML table (and/or CSV file).


# Requirements
You'll need:
  - A Linux server running NGINX.
  - Some NGINX log files to read/parse.
  - `zcat`, `sendmail`, and `whois` commands.
  - A valid email address that can be reached from your machine via sendmail.

### About Emails
If you're not running a local mail instance of some kind for `sendmail`, then this script may not operate exactly how you'd like.

It will be up to you to ensure your email configuration is correct to send the notification using sendmail.


# TODO
- [ ] Make the script more generic, for more logrotate use cases. Right now it heavily depends on very specific filenames.


# Usage
After configuring the variables inside the script to send the information to the right email, it's as simple as:
```
[me@pc ~]# python3 report_nginx.py
```

Alternatively, this can be configured in the `/etc/crontab` file like so:
```
  30 04 *  *  *    root    python3 /root/report_nginx.py 2>&1 >>/var/log/nginx-reporting.log
```
Feel free to change the output redirection or user `root` to something else, of course.

Thanks for viewing!