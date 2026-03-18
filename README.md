##### reconner.py -h

usage: reconnerv3.py [-h] [-f FILE] [-tt TARGET_TYPE] [--ra] [--to TO] [--th TH] [-v {0,1,2,3,4,5}] [-o OUTPUT] [domains ...]

reconner — Authorized Pentest Reconnaissance Toolkit

positional arguments:
  domains               Domain(s) to scan
```
options:
  -h, --help            show this help message and exit
  -f, --file FILE       File containing domains (one per line)
  -tt, --target-type TARGET_TYPE
                        Target type hint: generic, wordpress, laravel, django, nodejs, spring, rails, aspnet, php, vuejs, react, angular, joomla, drupal, magento, strapi, nextjs, nuxtjs
  --ra                  Random User-Agent per request
  --to TO               Request timeout in seconds (default: 10)
  --th TH               Thread count (default: 20)
  -v, --verbosity {0,1,2,3,4,5}
                        Verbosity 0-5 (default: 2)
  -o, --output OUTPUT   Output directory (default: ./recon_<domain>)
```
Examples:
```
  reconner.py example.com
  reconner.py example.com example2.com
  reconner.py -f domains.txt
  reconner.py example.com -v3 --th 30 --ra
  reconner.py example.com -o /tmp/recon_output
  reconner.py example.com -tt wordpress,laravel
```
