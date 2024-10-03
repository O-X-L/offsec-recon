#!/usr/bin/env python3

# Source: https://github.com/O-X-L/offsec-recon
# Copyright (C) 2024 Rath Pascal
# License: GPLv3

from json import dumps as json_dumps
from argparse import ArgumentParser
from itertools import product

from validators import domain as valid_domain
from dns.resolver import Resolver, NoAnswer, NXDOMAIN, NoNameservers

NAMESERVERS = ['1.1.1.1']

# see: https://en.wikipedia.org/wiki/IDN_homograph_attack
HOMOGRAPH = [
    ['I', 'Ӏ'],
    ['O', '0'],
    ['a', 'а'],
    ['c', 'с'],
    ['e', 'е'],
    ['o', 'о'],
    ['p', 'р'],
    ['x', 'х'],
    ['y', 'у'],
    ['3', 'З'],
    ['4', 'Ч'],
    ['6', 'б'],
    ['і', 'i'],
    ['ј', 'j'],
    ['ԛ', 'q'],
    ['ѕ', 's'],
    ['ԝ', 'w'],
    ['Ү', 'Y'],
    ['Ғ', 'F'],
    ['Ԍ', 'G'],
    ['ӓ', 'ä'],
    ['ӧ', 'ö'],
    ['ԁ', 'd'],
    ['һ', 'h'],
    ['ѵ', 'v'],
    ['β', 'ß'],
]


def _replace_char(src: str, idx: int, char: str) -> str:
    return src[:idx] + char + src[idx + 1:]


def _get_available_substitutions() -> list[dict]:
    # target idx => sub idx
    subs = []

    for idx_translate, h in enumerate(HOMOGRAPH):
        h_len = len(h)
        assert h_len == len(set(h))  # all chars inside a homograph list have to be unique

        for idx_original in range(h_len):
            char_original = h[idx_original]
            s = TARGET_DOM

            while s.find(char_original) != -1:
                idx_char_original = s.find(char_original)

                if idx_char_original == -1:
                    continue

                subs.append({
                    'o': idx_char_original,
                    't': idx_translate,
                })

                s = _replace_char(src=s, idx=idx_char_original, char='_')

    return subs


def _build_options(subs: list[dict]) -> list:
    opt_cnt = 0
    subs_map = []
    for sub in subs:
        t = HOMOGRAPH[sub['t']].copy()
        t.remove(TARGET_DOM[sub['o']])
        opt_cnt += len(t) ** 2
        for tc in t:
            subs_map.append({'o': sub['o'], 't': tc})

    if opt_cnt == 0:
        return []

    opts = []
    for o in product([True, False], repeat=opt_cnt):
        if max(o) == 0:
            # no change
            continue

        spoofed = TARGET_DOM
        for oi, ov in enumerate(o):
            if not ov:
                continue

            spoofed = _replace_char(src=spoofed, idx=subs_map[oi]['o'], char=subs_map[oi]['t'])

        spoofed = f'{spoofed}.{TARGET_TLD}'

        if not valid_domain(spoofed):
            continue

        opts.append(spoofed)

    return opts


def _check_if_registered(domains: list) -> dict:
    spoofs = {}
    dns = Resolver(configure=False)
    dns.nameservers = NAMESERVERS

    for d in domains:
        try:
            if len(dns.resolve(d, 'NS')) == 0:
                raise NoAnswer

            exists = True

        except NXDOMAIN:
            exists = False

        except (NoNameservers, NoAnswer):
            exists = 'unknown'

        spoofs[d] = {'registered': exists}

    return spoofs


def main():
    print(json_dumps(
        _check_if_registered(_build_options(_get_available_substitutions())),
        indent=4,
        ensure_ascii=ASCII
    ))


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('-t', '--target', help='Target domain', required=True, type=str)
    parser.add_argument('-a', '--ascii', help='Show spoofing domains in ASCII (show spoofed characters)', default=False, type=bool)
    parser.add_argument('-q', '--quiet', help='Do not show banner', default=False, type=bool)
    args = parser.parse_args()

    if not args.quiet:
        # pylint: disable=R0801
        print("""
#####################################################
USE YOUR POWERS TO SUPPORT THE GOOD SIDE OF HUMANITY!

Made by: OXL IT Services (github.com/O-X-L)
License: GPLv3
#####################################################
""")

    TARGET_DOM, TARGET_TLD = args.target.rsplit('.', 1)
    ASCII = args.ascii

    main()
