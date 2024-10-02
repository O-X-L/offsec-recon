# DNS / Domain Recon

We want to gather information about existing domains and the services behind them.

The included wordlist was copied from: [theMiddleBlue/DNSenum](https://github.com/theMiddleBlue/DNSenum) 

----

## How it works

* All IPs we find will get their PTR's looked-up
* Resolving the basic DNS records (NS, MX, DMARC, SPF)
  * Parsing SPF
* Pulling domains from [existing certificates](https://crt.sh)
* Checking if a wildcard DNS record is set
* Trying if domains from the provided wordlist can be resolved

----

## Other Tools

Make sure to also use other tools:

* [projectdiscovery/subfinder](https://github.com/projectdiscovery/subfinder)
* [projectdiscovery/alterx](https://github.com/projectdiscovery/alterx) (*sub-domain list generator*)
* [knock](https://github.com/guelfoweb/knock)
* [dnsdumpster](https://github.com/nmmapper/dnsdumpster)

Useful online services are linked in the output. (*see example below*)

----

Requirements: `pip install -r requirements.txt`

## Domain Enumeration

### Usage

```bash
python3 dns/domain_enum.py -h
> usage: domain_enum.py [-h] -t TARGET [-f FOLLOW] [-p THREADS] [-w WORDLIST]
> 
> options:
>   -h, --help            show this help message and exit
>   -t TARGET, --target TARGET
>                         Target domain or URL to scan
>   -f FOLLOW, --follow FOLLOW
>                         Recursively follow unrelated domains
>   -p THREADS, --threads THREADS
>                         Parallel threads to use
>   -w WORDLIST, --wordlist WORDLIST
>                         Wordlist to use

# example:
python3 dns/domain_enum.py google.com
```

Filter results using `jq`:

```bash
# get a simple list of all domains
cat dns/out/results_<DOMAIN>.json | jq 'keys | .[]'

# get all unique IPv4 addresses
cat dns/out/results_<DOMAIN>.json | jq -r '.[] | .ip | .ip4 | .[]' | sort | uniq

# get all IPv4 PTRs
cat dns/out/results_<DOMAIN>.json | jq -r '.[] | .ptr | .ip4 | .[]' | sort | uniq
```

----

### Output

#### Whois

```json
{
    "domain_name": "oxl.at",
    "registrar": "World4You Internet Services GmbH ( https://nic.at/registrar/61 )",
    "name_servers": [
        "ns1.world4you.at",
        "ns2.world4you.at"
    ],
    "name": "Domain Admin",
    "org": "World4You Internet Services GmbH",
    "address": "Hafenstrasse 35",
    "registrant_postal_code": "4020",
    "city": "Linz",
    "country": "Austria",
    "phone": "<data not disclosed>",
    "fax": "<data not disclosed>",
    "updated_date": [
        "2022-08-11 00:19:34",
        "2019-01-17 15:19:57"
    ],
    "email": "<data not disclosed>"
}
```

#### Domains/IPs

Note: If the target domain has a wildcard-record set, the DNS-lookup checks might overlook some generic pages as we ignore any record that is pointing to the same IPs as the wildcard-record does.

```json
{
    "oxl.at": {
        "shodan_url": "https://www.shodan.io/search?query=hostname%3Aoxl.at",
        "censys_url": "https://search.censys.io/search?resource=hosts&sort=RELEVANCE&per_page=25&virtual_hosts=INCLUDE&q=oxl.at",
        "google_site": "https://www.google.com/search?q=site%3Aoxl.at",
        "cert_search_url": "https://crt.sh/?q=oxl.at"
    },
    "*.oxl.at": {
        "ip": {
            "ip4": [
                "159.69.187.50"
            ],
            "ip6": [
                "2a01:4f8:c010:97b4::1"
            ]
        },
        "ptr": {
            "ip4": [
                "lb01.c.oxl.at."
            ],
            "ip6": []
        }
    },
    "lb01.c.oxl.at": {
        "ip": {
            "ip4": [
                "159.69.187.50"
            ],
            "ip6": [
                "2a01:4f8:c010:97b4::1"
            ]
        },
        "ptr": {
            "ip4": [
                "lb01.c.oxl.at."
            ],
            "ip6": []
        }
    },
    "__NS": [
        "ns1.world4you.at.",
        "ns2.world4you.at."
    ],
    "__MX": [
        "1 SMTP.GOOGLE.COM."
    ],
    "__TXT": [
        "\"v=spf1 mx include:_spf.oxl.at -all\"",
        "\"google-site-verification=FLcbs-psv67SmmFyw8NQvz4iDKWPHxIadE6C4qhC2_Y\""
    ],
    "static.220.170.181.135.clients.your-server.de": {
        "ip": {
            "ip4": [
                "135.181.170.220"
            ],
            "ip6": []
        },
        "ptr": {
            "ip4": [
                "static.220.170.181.135.clients.your-server.de."
            ],
            "ip6": []
        }
    },
    "d51d74.mail.host-svc.com": {
        "ip": {
            "ip4": [
                "49.13.245.115"
            ],
            "ip6": []
        },
        "ptr": {
            "ip4": [
                "d51d74.mail.host-svc.com."
            ],
            "ip6": []
        }
    },
    "__DMARC": [
        "\"v=DMARC1; p=reject; rua=mailto:dmarc@mail.host-svc.com; ruf=mailto:dmarc@mail.host-svc.com; aspf=s; adkim=s;\""
    ]
}
```

----

## Generate Spoofing Domains

This script basically replaces [spoofable characters](https://en.wikipedia.org/wiki/IDN_homograph_attack) in the provided domain name.

### Usage

```bash
python3 dns/domain_spoof.py  -h
> usage: domain_spoof.py [-h] -t TARGET [-a ASCII]
> 
> options:
>   -h, --help            show this help message and exit
>   -t TARGET, --target TARGET
>                         Target domain
>   -a ASCII, --ascii ASCII
>                         Show spoofing domains in ASCII (show spoofed characters)
>   -q QUIET, --quiet QUIET
>                         Do not show banner

python3 dns/domain_spoof.py -t oxl.com -a 1
```

### Output

In UTF-8 encoding

```json 
{
    "ox1.com": {
        "registered": true
    },
    "oxI.com": {
        "registered": true
    },
    "oxӀ.com": {
        "registered": false
    },
    "оxl.com": {
        "registered": false
    },
    "oхl.com": {
        "registered": false
    }
}
```

In ASCII encoding (`-a 1`)

```json
{
    "ox1.com": {
        "registered": true
    },
    "oxI.com": {
        "registered": true
    },
    "ox\u04c0.com": {
        "registered": false
    },
    "\u043exl.com": {
        "registered": false
    },
    "o\u0445l.com": {
        "registered": false
    }
}
```

----

## Sniff Domains and IPs from Service-Certificates

Dependencies: `apt install openssl grep`

### Usage

```bash
python3 dns/cert_sniff.py -h
> usage: cert_sniff.py [-h] -t TARGET
> 
> options:
>   -h, --help            show this help message and exit
>   -t TARGET, --target TARGET
>                         Target domain
>   -p PORT, --port PORT  Target port

python3 dns/cert_sniff.py -t oxl.at
```

### Output

```json
{
    "domains": [
        "ansibleguy.net",
        "global.oxl.at",
        "global.preview.oxl.at",
        "host-svc.com",
        "o-x-l.at",
        "o-x-l.co.at",
        "o-x-l.com",
        "o-x-l.net",
        "o-x-l.org",
        "oxl.app",
        "oxl.at",
        "oxl.co.at",
        "preview.oxl.at",
        "www.ansibleguy.net",
        "www.global.oxl.at",
        "www.host-svc.com",
        "www.o-x-l.at",
        "www.o-x-l.co.at",
        "www.o-x-l.com",
        "www.o-x-l.net",
        "www.o-x-l.org",
        "www.oxl.app",
        "www.oxl.at",
        "www.oxl.co.at"
    ],
    "ips": []
}
```
