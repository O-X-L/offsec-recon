# IP Metadata Recon

We want to gather information about IPs we have liked to the client.

You may be able to find related IPs using the DNS script.

This script utilizes the free [OXL ASN/ISP Database](https://github.com/O-X-L/geoip-asn) (*based on [PeeringDB](https://www.peeringdb.com/)*), [IPInfo API](https://ipinfo.io) and optional [Shodan API](https://shodan.io) to gather relevant information.

----

## Usage

First you have to create an IP-List file. It can contain IPs or subnets. IPv4 and IPv6 are supported.

```bash
python3 ips/main.py -h
> usage: main.py [-h] [-i IPLIST] [-o OUT_NAME] [-t IPINFO_TOKEN] [-s SHODAN_KEY]
> 
> options:
>   -h, --help            show this help message and exit
>   -i IPLIST, --iplist IPLIST
>                         IP-list to process
>   -o OUT_NAME, --out-name OUT_NAME
>                         Output file-name
>   -t IPINFO_TOKEN, --ipinfo-token IPINFO_TOKEN
>                         IPInfo API token (free => https://ipinfo.io/account/token)
>   -s SHODAN_KEY, --shodan-key SHODAN_KEY
>                         Shodan.io API key (paid => https://developer.shodan.io/api)

python3 ips/main.py -i my-ips.txt -t xxxxxxxxxxxxxx
```

Note: You might encounter issues with API rate-limits if you want to mass-lookup IPs.

----

## Output

Example:

```json
{
    "ip4": {
        "159.69.187.50": {
            "oxl_asn": {
                "asn": 24940,
                "org": "Hetzner Online GmbH"
            },
            "ipinfo_url_ip": "https://ipinfo.io/159.69.187.50",
            "censys_url": "https://search.censys.io/hosts/159.69.187.50",
            "ipinfo": {
                "ip": "159.69.187.50",
                "hostname": "lb01.c.oxl.at",
                "city": "Falkenstein",
                "region": "Saxony",
                "country": "DE",
                "loc": "50.4779,12.3713",
                "org": "AS24940 Hetzner Online GmbH",
                "postal": "08223",
                "timezone": "Europe/Berlin"
            }
        },
        "49.13.245.112": {
            "oxl_asn": {
                "asn": 24940,
                "org": "Hetzner Online GmbH"
            },
            "ipinfo_url_ip": "https://ipinfo.io/49.13.245.112",
            "censys_url": "https://search.censys.io/hosts/49.13.245.112",
            "ipinfo": {
                "ip": "49.13.245.112",
                "hostname": "static.112.245.13.49.clients.your-server.de",
                "city": "Gunzenhausen",
                "region": "Bavaria",
                "country": "DE",
                "loc": "49.1166,10.7597",
                "org": "AS24940 Hetzner Online GmbH",
                "postal": "91710",
                "timezone": "Europe/Berlin"
            }
        },
        "49.13.245.113": {
            "oxl_asn": {
                "asn": 24940,
                "org": "Hetzner Online GmbH"
            },
            "ipinfo_url_ip": "https://ipinfo.io/49.13.245.113",
            "censys_url": "https://search.censys.io/hosts/49.13.245.113",
            "ipinfo": {
                "ip": "49.13.245.113",
                "hostname": "static.113.245.13.49.clients.your-server.de",
                "city": "Gunzenhausen",
                "region": "Bavaria",
                "country": "DE",
                "loc": "49.1166,10.7597",
                "org": "AS24940 Hetzner Online GmbH",
                "postal": "91710",
                "timezone": "Europe/Berlin"
            }
        },
        "49.13.245.114": {
            "oxl_asn": {
                "asn": 24940,
                "org": "Hetzner Online GmbH"
            },
            "ipinfo_url_ip": "https://ipinfo.io/49.13.245.114",
            "censys_url": "https://search.censys.io/hosts/49.13.245.114",
            "ipinfo": {
                "ip": "49.13.245.114",
                "hostname": "static.114.245.13.49.clients.your-server.de",
                "city": "Gunzenhausen",
                "region": "Bavaria",
                "country": "DE",
                "loc": "49.1166,10.7597",
                "org": "AS24940 Hetzner Online GmbH",
                "postal": "91710",
                "timezone": "Europe/Berlin"
            }
        },
        "49.13.245.115": {
            "oxl_asn": {
                "asn": 24940,
                "org": "Hetzner Online GmbH"
            },
            "ipinfo_url_ip": "https://ipinfo.io/49.13.245.115",
            "censys_url": "https://search.censys.io/hosts/49.13.245.115",
            "ipinfo": {
                "ip": "49.13.245.115",
                "hostname": "d51d74.mail.host-svc.com",
                "city": "Gunzenhausen",
                "region": "Bavaria",
                "country": "DE",
                "loc": "49.1166,10.7597",
                "org": "AS24940 Hetzner Online GmbH",
                "postal": "91710",
                "timezone": "Europe/Berlin"
            }
        }
    },
    "ip6": {
        "2a01:4f8:c010:97b4::1": {
            "oxl_asn": {
                "asn": 24940,
                "org": "Hetzner Online GmbH"
            },
            "ipinfo_url_ip": "https://ipinfo.io/2a01:4f8:c010:97b4::1",
            "censys_url": "https://search.censys.io/hosts/2a01:4f8:c010:97b4::1",
            "ipinfo": {
                "ip": "2a01:4f8:c010:97b4::1",
                "city": "Falkenstein",
                "region": "Saxony",
                "country": "DE",
                "loc": "50.4779,12.3713",
                "org": "AS24940 Hetzner Online GmbH",
                "postal": "08223",
                "timezone": "Europe/Berlin"
            }
        }
    },
    "asn": {
        "24940": {
            "asn": 24940,
            "contacts": {},
            "info": {
                "aka": "",
                "info_ipv6": true,
                "info_multicast": false,
                "info_never_via_route_servers": false,
                "info_prefixes4": 1000,
                "info_prefixes6": 200,
                "info_ratio": "Mostly Outbound",
                "info_scope": "Europe",
                "info_traffic": "5-10Tbps",
                "info_types": [
                    "Content"
                ],
                "info_unicast": true,
                "irr_as_set": "AS-HETZNER",
                "looking_glass": "",
                "name": "Hetzner Online",
                "name_long": "",
                "notes": "",
                "policy_contracts": "Not Required",
                "policy_general": "Open",
                "policy_locations": "Not Required",
                "policy_ratio": false,
                "policy_url": "https://docs.hetzner.com/general/others/peering-policy/",
                "rir_status": "ok",
                "rir_status_updated": "2024-06-26 04:47:55",
                "route_server": "",
                "social_media": [
                    {
                        "identifier": "https://www.hetzner.com",
                        "service": "website"
                    }
                ],
                "status": "ok",
                "status_dashboard": "",
                "website": "https://www.hetzner.com"
            },
            "organization": {
                "address1": "Industriestrasse 25",
                "address2": "",
                "aka": "",
                "city": "Gunzenhausen",
                "country": "DE",
                "floor": "",
                "latitude": 0.0,
                "longitude": 0.0,
                "name": "Hetzner Online GmbH",
                "name_long": "",
                "notes": "",
                "social_media": [
                    {
                        "identifier": "http://www.hetzner.com",
                        "service": "website"
                    }
                ],
                "state": "Baveria",
                "status": "ok",
                "suite": "",
                "website": "http://www.hetzner.com",
                "zipcode": "91710"
            },
            "ipinfo_url_asn": "https://ipinfo.io/AS24940"
        }
    }
}
```
