#!/usr/bin/env python3

from pathlib import Path
from sys import argv
from threading import Thread, Lock
from time import sleep
from json import dumps as json_dumps

from dns.resolver import Resolver, NoAnswer, NXDOMAIN
from dns.exception import SyntaxError

BASE_DIR = Path(__file__).parent.resolve()

NAMESERVERS = ['1.1.1.1']
WORDLIST = f'{BASE_DIR}/subdom-5k.txt'
WILDCARD_RANDOM = 'ksdljfdlsnesfel3498394ßskeöskfölsjefk'
THREADS = 10
FOLLOW_OTHER = False  # if ptrs/spf points to other parent-domains should be scanned (1-layer deep)

TARGET = argv[1]
TARGET_BASE = TARGET.rsplit('.', 1)[0]
dns_resolver = Resolver(configure=False)
dns_resolver.nameservers = NAMESERVERS


def dns_lookup(dns: str) -> tuple[bool, dict]:
    ips = {}
    try:
        ips['ip4'] = [r.to_text() for r in dns_resolver.resolve(dns, 'A')]

    except (NoAnswer, NXDOMAIN):
        ips['ip4'] = []

    try:
        ips['ip6'] = [r.to_text() for r in dns_resolver.resolve(dns, 'AAAA')]

    except (NoAnswer, NXDOMAIN):
        ips['ip6'] = []

    return (len(ips['ip4']) > 0 or len(ips['ip6']) > 0), ips


def ptr_lookups(ips: list[str]) -> list:
    ptrs = []

    for ip in ips:
        try:
            ptrs.extend([p.to_text() for p in dns_resolver.resolve_address(ip)])

        except (NoAnswer, NXDOMAIN, SyntaxError):
            continue

    return ptrs


def ptr_lookup_ips(ips: dict) -> dict:
    return {
        'ip4': ptr_lookups(ips['ip4']),
        'ip6': ptr_lookups(ips['ip6']),
    }


def subdomain(sub: str) -> str:
    return f'{sub.strip()}.{TARGET}'


def allow_follow(dom: str) -> bool:
    return FOLLOW_OTHER or dom.find(TARGET_BASE) != -1  # allow follow to related domains


def parse_spf(txt_entries: list[str]) -> list:
    for e in txt_entries:
        if e.find('v=spf1') != -1:
            spf_domains = []

            for p in e.split(' '):
                try:
                    pk, pv = p.split(':', 1)

                except ValueError:
                    continue

                if pk in ['ip4', 'ip6']:
                    spf_domains.extend(ptr_lookups([pv]))

                elif pk in ['a']:
                    spf_domains.append(pv)

                elif pk in ['include', 'redirect']:
                    # recurse if we should follow the lead
                    if not allow_follow(pv):
                        continue

                    try:
                        spf_domains.extend(parse_spf(
                            [r.to_text() for r in dns_resolver.resolve(pv, 'TXT')]
                        ))

                    except (NoAnswer, NXDOMAIN):
                        pass

            return spf_domains

    return []


def main():
    result_lock = Lock()
    results = {}

    def _get_ips_if_relevant(dom: str, wildcard_filter: bool = True) -> (dict, None):
        exists, ips = dns_lookup(dom)
        if not exists:
            return

        if wildcard_filter and wildcard_exists and ips['ip4'] == wildcard_ips['ip4'] and ips['ip6'] == wildcard_ips['ip6']:
            return

        return ips

    def _check_ptrs(ptrs: dict, ptr_domain: str):
        # todo: create cleaner approach for recursive ptr processing
        for ipp in ['ip4', 'ip6']:
            for d in ptrs[ipp]:
                d = d[:-1]
                if d != ptr_domain and allow_follow(d) and d not in results:
                    ips2 = _get_ips_if_relevant(d, False)
                    if ips2 is None:
                        continue

                    print('FOUND:', d, '(PTR)')
                    ptrs2 = ptr_lookup_ips(ips2)

                    with result_lock:
                        results[d] = {'ip': ips2, 'ptr': ptrs2}

    def _lookup(dom: str):
        if dom.endswith('.'):
            dom = dom[:-1]

        ips = _get_ips_if_relevant(dom)
        if ips is None:
            return

        print('FOUND:', dom)

        ptrs = ptr_lookup_ips(ips)

        with result_lock:
            results[dom] = {'ip': ips, 'ptr': ptrs}

        _check_ptrs(ptrs, dom)

    def _lookup_sub(word: str):
        _lookup(subdomain(word))

    # WILDCARD records
    wildcard_exists, wildcard_ips = dns_lookup(subdomain(WILDCARD_RANDOM))
    print('HAS WILDCARD:', wildcard_exists)
    if wildcard_exists:
        wildcard_ptrs = ptr_lookup_ips(wildcard_ips)
        results[subdomain('*')] = {'ip': wildcard_ips, 'ptr': wildcard_ptrs}
        _check_ptrs(wildcard_ptrs, subdomain('*'))

        print('WARNING: We will ignore all records that match the wildcard. Some generic ones might be missing!')
        print()

    # BASIC records
    results['__NS'] = [r.to_text() for r in dns_resolver.resolve(TARGET, 'NS')]

    try:
        results['__MX'] = [r.to_text() for r in dns_resolver.resolve(TARGET, 'MX')]

    except (NoAnswer, NXDOMAIN):
        pass

    try:
        results['__TXT'] = [r.to_text() for r in dns_resolver.resolve(TARGET, 'TXT')]
        print('PARSING SPF')
        for sd in parse_spf(results['__TXT']):
            _lookup(sd)

    except (NoAnswer, NXDOMAIN):
        pass

    try:
        results['__DMARC'] = [r.to_text() for r in dns_resolver.resolve(subdomain('_dmarc'), 'TXT')]

    except (NoAnswer, NXDOMAIN):
        pass

    # MAIN CHECKS
    print()
    print('STARTING SUBDOMAIN PROBES')

    with open(WORDLIST, 'r', encoding='utf-8') as f:
        wordlist = f.readlines()

    try:
        batch = 0
        while batch * THREADS < len(wordlist):
            threads = []
            for i in range(THREADS):
                threads.append(Thread(
                    target=_lookup_sub,
                    kwargs={'word': wordlist[(batch * THREADS) + i]},
                ))

            for t in threads:
                t.start()

            threads_done = False
            while not threads_done:
                threads_done = all([not t.is_alive() for t in threads])
                sleep(0.05)

            batch += 1

    except KeyboardInterrupt:
        print()
        print('WARNING: SCAN INTERRUPTED')
        pass

    with open(f'results_{TARGET}.json', 'w', encoding='utf-8') as f:
        f.write(json_dumps(results, indent=4))

    print('DONE')

if __name__ == '__main__':
    main()
