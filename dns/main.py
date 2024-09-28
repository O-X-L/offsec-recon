#!/usr/bin/env python3

from pathlib import Path
from sys import argv
from threading import Thread, Lock
from time import sleep, time
from json import dumps as json_dumps

from dns.resolver import Resolver, NoAnswer, NXDOMAIN, LifetimeTimeout, NoNameservers
from dns.exception import SyntaxError
from whois import whois

BASE_DIR = Path(__file__).parent.resolve()

NAMESERVERS = ['1.1.1.1']
WORDLIST = f'{BASE_DIR}/subdom-5k.txt'
WILDCARD_RANDOM = 'ksdljfdlsnesfel3498394ßskeöskfölsjefk'
THREADS = 50
FOLLOW_OTHER = False  # if ptrs/spf points to other parent-domains should be scanned (1-layer deep)
TARGET = argv[1]
TARGET_BASE = TARGET.rsplit('.', 1)[0]


def subdomain(sub: str) -> str:
    return f'{sub.strip()}.{TARGET}'


def allow_follow(dom: str) -> bool:
    return FOLLOW_OTHER or \
        dom.find(TARGET_BASE) != -1  # allow follow to related domains


class DNSRecon:
    def __init__(self):
        self.lock = Lock()
        self.results = {}
        self.dns = Resolver(configure=False)
        self.dns.nameservers = NAMESERVERS
        self.wildcard_exists = False
        self.wildcard_ips = {}
        self.start_time = time()

    def run(self):
        self._process_basic_records()
        self.wildcard_exists, self.wildcard_ips = self._check_for_wildcard()
        try:
            self._process_wordlist()

        except KeyboardInterrupt:
            print()
            print('WARNING: SCAN INTERRUPTED')

        self._save_results()
        print('DONE')

    def _save_results(self):
        print('SAVING INFORMATION')

        with open(f'{BASE_DIR}/out/whois_{TARGET}.json', 'w', encoding='utf-8') as f:
            f.write(json_dumps(whois(TARGET), indent=4, default=str))

        with open(f'{BASE_DIR}/out/results_{TARGET}.json', 'w', encoding='utf-8') as f:
            f.write(json_dumps(self.results, indent=4))

    def _process_wordlist(self):
        print()
        print('STARTING SUBDOMAIN PROBES')

        with open(WORDLIST, 'r', encoding='utf-8') as f:
            wordlist = f.readlines()

        batch = 0
        while batch * THREADS < len(wordlist):
            threads = []
            for i in range(THREADS):
                idx = (batch * THREADS) + i
                if idx > len(wordlist) - 1:
                    break

                threads.append(Thread(
                    target=self._lookup_sub,
                    kwargs={'word': wordlist[idx]},
                ))
                if idx % 500 == 0 and idx != 0:
                    print(
                        f'INFO: {int((100 / len(wordlist)) * idx)}% ({idx}/{len(wordlist)}) '
                        f'in {int(time()-self.start_time)}s'
                    )

            for t in threads:
                t.start()

            threads_done = False
            while not threads_done:
                threads_done = all([not t.is_alive() for t in threads])
                sleep(0.05)

            batch += 1

    def _process_basic_records(self):
        try:
            self.results['__NS'] = [r.to_text() for r in self.dns.resolve(TARGET, 'NS')]

        except NXDOMAIN:
            print(f"ERROR: The domain '{TARGET}' is not resolvable! Check it for typos!")
            exit(1)

        try:
            self.results['__MX'] = [r.to_text() for r in self.dns.resolve(TARGET, 'MX')]

        except (NoAnswer, NXDOMAIN):
            pass

        try:
            self.results['__TXT'] = [r.to_text() for r in self.dns.resolve(TARGET, 'TXT')]
            print('PARSING SPF')
            for sd in self._parse_spf(self.results['__TXT']):
                self._lookup(sd)

        except (NoAnswer, NXDOMAIN):
            pass

        try:
            self.results['__DMARC'] = [r.to_text() for r in self.dns.resolve(subdomain('_dmarc'), 'TXT')]

        except (NoAnswer, NXDOMAIN):
            pass

    def _check_for_wildcard(self):
        wildcard_exists, wildcard_ips = self._name_lookup(subdomain(WILDCARD_RANDOM))
        print('HAS WILDCARD:', wildcard_exists)
        if wildcard_exists:
            wildcard_ptrs = self._ptr_lookup_ips(wildcard_ips)
            self.results[subdomain('*')] = {'ip': wildcard_ips, 'ptr': wildcard_ptrs}
            self._check_ptrs(wildcard_ptrs, subdomain('*'))

            print('WARNING: We will ignore all records that match the wildcard. Some generic ones might be missing!')
            print()

        return wildcard_exists, wildcard_ips

    def _name_lookup(self, dns: str) -> tuple[bool, dict]:
        ips = {}
        try:
            retry = 0
            while True:
                try:
                    ips['ip4'] = [r.to_text() for r in self.dns.resolve(dns, 'A')]
                    break

                except (LifetimeTimeout, NoNameservers):
                    if retry >= 5:
                        raise NXDOMAIN

                    retry += 1
                    continue



        except (NoAnswer, NXDOMAIN):
            ips['ip4'] = []

        try:
            retry = 0
            while True:
                try:
                    ips['ip6'] = [r.to_text() for r in self.dns.resolve(dns, 'AAAA')]
                    break

                except (LifetimeTimeout, NoNameservers):
                    if retry >= 5:
                        raise NXDOMAIN

                    retry += 1
                    continue

        except (NoAnswer, NXDOMAIN):
            ips['ip6'] = []

        return (len(ips['ip4']) > 0 or len(ips['ip6']) > 0), ips

    def _ptr_lookups(self, ips: list[str]) -> list:
        ptrs = []

        for ip in ips:
            try:
                ptrs.extend([p.to_text() for p in self.dns.resolve_address(ip)])

            except (NoAnswer, NXDOMAIN, SyntaxError):
                continue

        return ptrs


    def _ptr_lookup_ips(self, ips: dict) -> dict:
        return {
            'ip4': self._ptr_lookups(ips['ip4']),
            'ip6': self._ptr_lookups(ips['ip6']),
        }


    def _parse_spf(self, txt_entries: list[str]) -> list:
        for e in txt_entries:
            if e.find('v=spf1') != -1:
                spf_domains = []

                for p in e.split(' '):
                    try:
                        pk, pv = p.split(':', 1)

                    except ValueError:
                        continue

                    if pk in ['ip4', 'ip6']:
                        spf_domains.extend(self._ptr_lookups([pv]))

                    elif pk in ['a']:
                        spf_domains.append(pv)

                    elif pk in ['include', 'redirect']:
                        # recurse if we should follow the lead
                        if not allow_follow(pv):
                            continue

                        try:
                            spf_domains.extend(self._parse_spf(
                                [r.to_text() for r in self.dns.resolve(pv, 'TXT')]
                            ))

                        except (NoAnswer, NXDOMAIN):
                            pass

                return spf_domains

        return []

    def _get_ips_if_relevant(self, dom: str, wildcard_filter: bool = True) -> (dict, None):
        if dom in self.results:
            return

        exists, ips = self._name_lookup(dom)
        if not exists:
            return

        if wildcard_filter and self.wildcard_exists and \
                ips['ip4'] == self.wildcard_ips['ip4'] and ips['ip6'] == self.wildcard_ips['ip6']:
            return

        return ips

    def _check_ptrs(self, ptrs: dict, ptr_domain: str):
        # todo: create cleaner approach for recursive ptr processing
        for ipp in ['ip4', 'ip6']:
            for d in ptrs[ipp]:
                d = d[:-1]
                if d != ptr_domain and allow_follow(d) and d not in self.results:
                    ips2 = self._get_ips_if_relevant(d, False)
                    if ips2 is None:
                        continue

                    print('FOUND:', d, '(PTR)')
                    ptrs2 = self._ptr_lookup_ips(ips2)

                    with self.lock:
                        self.results[d] = {'ip': ips2, 'ptr': ptrs2}

    def _lookup(self, dom: str):
        dom = dom.lower()
        if dom.endswith('.'):
            dom = dom[:-1]

        ips = self._get_ips_if_relevant(dom)
        if ips is None:
            return

        print('FOUND:', dom)

        ptrs = self._ptr_lookup_ips(ips)

        with self.lock:
            self.results[dom] = {'ip': ips, 'ptr': ptrs}

        self._check_ptrs(ptrs, dom)

    def _lookup_sub(self, word: str):
        self._lookup(subdomain(word))


if __name__ == '__main__':
    DNSRecon().run()
