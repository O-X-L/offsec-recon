#!/usr/bin/env python3

# Source: https://github.com/O-X-L/offsec-recon
# Copyright (C) 2024 Rath Pascal
# License: GPLv3

from json import dumps as json_dumps
from argparse import ArgumentParser
from itertools import permutations

from validators import domain as valid_domain
from dns.resolver import Resolver, NoAnswer, NXDOMAIN

NAMESERVERS = ['1.1.1.1']

# see: https://en.wikipedia.org/wiki/IDN_homograph_attack
HOMOGRAPH = [
    ['l', '1', 'I', 'Ӏ'],
    ['O', '0'],
    ['m', 'rn'],
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

def main():
    spoofs = {}
    dns = Resolver(configure=False)
    dns.nameservers = NAMESERVERS

    # pylint: disable=C0200,R1702
    for hl in HOMOGRAPH:
        for i in range(len(hl)):
            if hl[i] in TARGET_DOM:
                for i2 in range(len(hl)):
                    if i == i2:
                        continue

                    char_s = hl[i2]

                    # get indices of all characters to replace
                    ri = []
                    ris = TARGET_DOM
                    while ris.find(hl[i]) != -1:
                        char_idx = ris.find(hl[i])
                        ri.append(char_idx)
                        ris= ris[:char_idx] + '_' + ris[char_idx + 1:]

                    for permutation_len in range(1, len(ri) + 1):
                        for replace_idx in permutations(ri, permutation_len):
                            s = TARGET_DOM
                            for i3 in replace_idx:
                                s = s[:i3] + char_s + s[i3+1:]

                            s = f'{s}.{TARGET_TLD}'

                            if not valid_domain(s):
                                continue

                            try:
                                if len(dns.resolve(s, 'NS')) == 0:
                                    raise NoAnswer

                                exists = True

                            except (NoAnswer, NXDOMAIN):
                                exists = False

                            spoofs[s] = {'registered': exists}

    print(json_dumps(spoofs, indent=4, ensure_ascii=ASCII))


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
