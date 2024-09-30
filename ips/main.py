#!/usr/bin/env python3

# Source: https://github.com/O-X-L/offsec-recon
# Copyright (C) 2024 Rath Pascal
# License: GPLv3

from pathlib import Path
from argparse import ArgumentParser
from ipaddress import IPv4Address, IPv6Address, AddressValueError, IPv4Network, IPv6Network, NetmaskValueError
from json import dumps as json_dumps
from time import time

from httpx import request

BASE_DIR = Path(__file__).parent.resolve()

OXL_IP_API = 'https://geoip.oxl.at/api/ip'
SHODAN_IP_API = 'https://api.shodan.io/shodan/host'
IPINFO_URL = 'https://ipinfo.io'

class IPRecon:
    def __init__(self):
        self.results = {'ip4': {}, 'ip6': {}, 'asn': {}}
        self.iplist = []

    def run(self):
        self._load_iplist()
        self._lookup_ips()
        self._save_results()
        print('DONE')

    def _load_iplist(self):
        print('LOADING IPLIST')
        with open(IPLIST, 'r', encoding='utf-8') as f:
            for l in f.readlines():
                l = l.strip()
                for k in [IPv4Address, IPv6Address, IPv4Network, IPv6Network]:
                    try:
                        lk = k(l)
                        self.iplist.append(lk)
                        break

                    except (AddressValueError, NetmaskValueError):
                        continue

    def _save_results(self):
        print('SAVING INFORMATION')

        with open(f'{BASE_DIR}/out/results_{OUT_NAME}.json', 'w', encoding='utf-8') as f:
            f.write(json_dumps(self.results, indent=4))

    def _lookup_ips(self):
        print('QUERYING IP-METADATA')

        try:
            for ip_or_net in self.iplist:
                if isinstance(ip_or_net, IPv4Network):
                    data_oxl_asn = None
                    for ip in ip_or_net:
                        if data_oxl_asn is None:
                            data_oxl_asn = self._lookup_api_oxl_asn(ip)

                        self._lookup_ip(ip, data_oxl_asn=data_oxl_asn)

                else:
                    self._lookup_ip(
                        ip_or_net,
                        data_oxl_asn=self._lookup_api_oxl_asn(ip_or_net),
                    )

        except KeyboardInterrupt:
            print()
            print('WARNING: SCAN INTERRUPTED')

    def _lookup_ip(self, ip: (IPv4Address, IPv6Address), data_oxl_asn: dict):
        d = {
            'oxl_asn': data_oxl_asn,
            'ipinfo_url_ip': f"{IPINFO_URL}/{ip}",
        }

        if IPINFO_TOKEN != '':
            d['ipinfo'] = self._lookup_api_ipinfo(ip)
            ipinfo_asn = d['ipinfo']['org'].split(' ', 1)[0]
            if 'asn' not in data_oxl_asn or ipinfo_asn[2:] != str(data_oxl_asn['asn']):
                d['ipinfo_url_asn'] = f"{IPINFO_URL}/{ipinfo_asn}"

        if SHODAN_KEY != '':
            d['shodan'] = self._lookup_api_shodan(ip)

        if isinstance(ip, IPv4Address):
            self.results['ip4'][f'{ip}'] = d

        else:
            self.results['ip6'][f'{ip}'] = d

    def _lookup_api_oxl_asn(self, ip: (IPv4Address, IPv6Address)) -> dict:
        d = self._lookup_api(f"{OXL_IP_API}/{ip}")
        if len(d) == 0:
            return d

        d['ipinfo_url_asn'] = f"{IPINFO_URL}/AS{d['asn']}"

        if d['asn'] not in self.results['asn']:
            self.results['asn'][d['asn']] = d

        return {'asn': d['asn'], 'org': d['organization']['name']}

    def _lookup_api_ipinfo(self, ip: (IPv4Address, IPv6Address)) -> dict:
        return self._lookup_api(f"{IPINFO_URL}/{ip}?token={IPINFO_TOKEN}")

    def _lookup_api_shodan(self, ip: (IPv4Address, IPv6Address)) -> dict:
        return self._lookup_api(f"{SHODAN_IP_API}/{ip}?key={SHODAN_KEY}")

    @staticmethod
    def _lookup_api(url: str) -> dict:
        resp = request(
            method='get',
            url=url,
            headers={'User-Agent': 'OXL OffSec-Recon IP-Lookup (https://github.com/O-X-L/offsec-recon)'},
        )

        if resp.status_code != 200:
            print(f'ERROR: API Lookup failed with code {resp.status_code} ({url})')
            return {}

        return resp.json()


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('-i', '--iplist', help='IP-list to process', default=f'{BASE_DIR}/ips.txt', type=str)
    parser.add_argument('-o', '--out-name', help='Output file-name', default=f'{int(time())}', type=str)
    parser.add_argument(
        '-t', '--ipinfo-token', help=f'IPInfo API token (free => {IPINFO_URL}/account/token)',
        type=str, required=False, default='',
    )
    parser.add_argument(
        '-s', '--shodan-key', help='Shodan.io API key (paid => https://developer.shodan.io/api)',
        type=str, required=False, default='',
    )

    args = parser.parse_args()

    if args.iplist.find('/') == -1:
        IPLIST = BASE_DIR / args.iplist

    else:
        IPLIST = args.iplist

    OUT_NAME = args.out_name
    IPINFO_TOKEN = args.ipinfo_token
    SHODAN_KEY = args.shodan_key

    IPRecon().run()
