#!/usr/bin/env python3

# Source: https://github.com/O-X-L/offsec-recon
# Copyright (C) 2024 Rath Pascal
# License: GPLv3

from subprocess import Popen as ProcessOpen
from subprocess import PIPE, TimeoutExpired, SubprocessError, CalledProcessError
from json import dumps as json_dumps
from argparse import ArgumentParser

from validators import domain as valid_domain
from dns.resolver import Resolver, NoAnswer, NXDOMAIN

NAMESERVERS = ['1.1.1.1']


def _process(cmd: str, timeout_sec: int = None, shell: bool = False) -> str:
    try:
        with ProcessOpen(
            cmd,
            shell=shell,
            stdout=PIPE,
        ) as p:
            b_stdout, _ = p.communicate(timeout=timeout_sec)
            stdout = b_stdout.decode('utf-8').strip()

    except (TimeoutExpired, SubprocessError, CalledProcessError, OSError, IOError):
        stdout = 'str(error)'

    return stdout


def get_web_cert_san(domain: str) -> (str, None):
    return _process(
        cmd=f"openssl s_client -connect {domain}:{PORT} -status </dev/null 2>/dev/null | "
            "openssl x509 -noout -text | "
            "grep 'Subject Alternative Name:' -A 1 | "
            "grep 'DNS:'",
        timeout_sec=3,
        shell=True,
    )


def main():
    dns = Resolver(configure=False)
    dns.nameservers = NAMESERVERS

    cert_data = {
        'domains': [],
        'ips': [],
    }

    targets = [TARGET]
    if TARGET.startswith('www.'):
        targets.append(TARGET[4:])

    else:
        targets.append(f'www.{TARGET}')

    try:
        ips = [r.to_text() for r in dns.resolve(TARGET, 'A')]
        targets.extend(ips)
        for ip in ips:
            targets.extend([p.to_text() for p in dns.resolve_address(ip)])

    except (NoAnswer, NXDOMAIN):
        pass

    try:
        ips = [r.to_text() for r in dns.resolve(TARGET, 'AAAA')]
        targets.extend(ips)
        for ip in ips:
            targets.extend([p.to_text() for p in dns.resolve_address(ip)])

    except (NoAnswer, NXDOMAIN):
        pass

    for t in targets:
        for san in get_web_cert_san(t).split(','):
            san = san.strip()
            try:
                k, v = san.split(':', 1)
                if k == 'DNS':
                    if valid_domain(v):
                        cert_data['domains'].append(v)

                elif k == 'IP':
                    cert_data['ips'].append(v)

            except ValueError:
                continue

    cert_data['domains'] = list(set(cert_data['domains']))
    cert_data['domains'].sort()
    cert_data['ips'] = list(set(cert_data['ips']))
    cert_data['ips'].sort()
    print(json_dumps(cert_data, indent=4))


if __name__ == '__main__':
    # pylint: disable=R0801
    print("""
#####################################################
USE YOUR POWERS TO SUPPORT THE GOOD SIDE OF HUMANITY!

Made by: OXL IT Services (github.com/O-X-L)
License: GPLv3
#####################################################
""")

    parser = ArgumentParser()
    parser.add_argument('-t', '--target', help='Target domain', required=True, type=str)
    parser.add_argument('-p', '--port', help='Target port', default=443, type=int)

    args = parser.parse_args()

    TARGET = args.target
    PORT = args.port

    main()
