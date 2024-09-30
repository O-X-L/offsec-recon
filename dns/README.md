# DNS / Domain Recon

We want to gather information about existing domains and the services behind them.

The included wordlist was copied from: [theMiddleBlue/DNSenum](https://github.com/theMiddleBlue/DNSenum) 

## Usage

Requirements: `pip install -r requirements.txt`

```bash
python3 dns/main.py -h
> usage: main.py [-h] -t TARGET [-f FOLLOW] [-p THREADS] [-w WORDLIST]
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
python3 dns/main.py google.com
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

## Output

### Whois

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

### Domains/IPs

Note: If the target domain has a wildcard-record set, the DNS-lookup checks might overlook some generic pages as we ignore any record that is pointing to the same IPs as the wildcard-record does.

```json
{
    "oxl.at": {
        "shodan_url": "https://www.shodan.io/search?query=hostname%3Aoxl.at",
        "censys_url": "https://search.censys.io/search?resource=hosts&sort=RELEVANCE&per_page=25&virtual_hosts=INCLUDE&q=oxl.at",
        "google_site": "https://www.google.com/search?q=site%3Aoxl.at"
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

