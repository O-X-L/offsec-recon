#!/usr/bin/env python3

# Source: https://github.com/O-X-L/offsec-recon
# Copyright (C) 2024 Rath Pascal
# License: GPLv3

from time import sleep
from subprocess import Popen as ProcessOpen
from re import sub as regex_replace
from re import findall as regex_find
from json import dumps as json_dumps
from pathlib import Path
from argparse import ArgumentParser

import pyautogui
import pyperclip
from validators import domain as valid_domain

pyautogui.FAILSAFE = True
pyautogui.PAUSE = 0.2

CHROMIUM_BIN = 'chromium-browser'
# NOTE: positions are optimized for full-hd screen
URL_BAR = (pyautogui.size()[0] / 3, 80)
CONSOLE_HTML = (1800, 155)

LINK_STATICS_EXT = [
    'css', 'js', 'json',
    'png', 'jpg', 'jpeg', 'webp', 'ico', 'svg', 'gif',
    'woff', 'woff2', 'tff',
    'webmanifest',
    'ics', 'vcf', 'pdf', 'docx',
    'exe',
]
LINK_CONTACT_BEG = ['mailto:', 'tel:', 'callto:']
LINK_IGNORE_BEG = ['javascript:', '#']
LINK_PART_NO_FOLLOW = [
    # non HTML content
    'wp-content/', 'wp-json/', 'xmlrpc.php', ':+', '/feed/',
    # social media
    'facebook.com', '//x.com', 'twitter.com', 'instagram.com', 'xing.com', 'linkedin.com', 'pinterest.com',
    'youtube.com', 'youtu.be', 'www.amazon.de',
]
BASE_DIR = Path(__file__).parent.resolve()


def safe_url_key(url: str) -> str:
    url = url.replace('http://', '').replace('https://', '')
    if url.endswith('/'):
        url = url[:-1]

    if url.find('#') != -1:
        url = url.split('#', 1)[0]

    return regex_replace(r'[^a-zA-Z0-9\-\.]', '_', url)


def url_domain(url: str) -> str:
    return url.replace('http://', '').replace('https://', '').split('/', 1)[0]


def allow_follow(url: str) -> bool:
    # allow follow to related domains
    allow_other = False
    for o in FOLLOW_ALLOW_OTHER_LIST:
        if url.find(o) != -1:
            allow_other = True
            break

    return allow_other or url.find(TARGET_BASE) != -1


class WebCrawlerRecon:
    def __init__(self):
        self.results = {}
        cache_dir = Path(CACHE_DIR)
        cache_dir.mkdir(exist_ok=True)

    def run(self):
        with ProcessOpen(
                f'{CHROMIUM_BIN} --icognito --guest --disable-popup-blocking=false '
                f'--noerrdialogs --disable-infobars --disable-dev-shm-usage '
                f'--no-first-run --no-default-browser-check --start-maximized >/dev/null 2>/dev/null',
                shell=True,
        ) as browser:
            self._init_browser()
            self.download_website(TARGET)
            try:
                self.analyze_website(TARGET)

            except (KeyboardInterrupt, FileNotFoundError):
                print()
                print('WARNING: SCAN INTERRUPTED')

            self._save_results()
            print('DONE')

            browser.terminate()
            browser.kill()

    def _save_results(self):
        print('SAVING INFORMATION')

        with open(f'{BASE_DIR}/out/{safe_url_key(TARGET)}.json', 'w', encoding='utf-8') as f:
            f.write(json_dumps(self.results, indent=4))

    @staticmethod
    def _init_browser() :
        sleep(2)
        pyautogui.leftClick(URL_BAR[0], URL_BAR[1])  # get focus
        pyautogui.hotkey('f12')  # open dev console
        sleep(1)

    def download_website(self, url: str):
        surl = safe_url_key(url)
        if surl in self.results or url.find('<html') != -1:
            return

        print('DL:', len(self.results), url)
        pyautogui.leftClick(URL_BAR[0], URL_BAR[1])

        tries = 0
        url_ok = False
        while tries < 3 and not url_ok:
            pyperclip.copy(url)
            if pyperclip.paste().find('<html') == -1:
                url_ok = True

            tries += 1

        if tries >= 3:
            print('ERROR: Failed to copy-paste URL')
            return

        pyautogui.hotkey('ctrl', 'v')
        pyautogui.typewrite(['enter'])
        sleep(PAGE_LOAD_WAIT)
        pyautogui.leftClick(CONSOLE_HTML[0], CONSOLE_HTML[1])
        pyautogui.typewrite(['down'])

        tries = 0
        while tries < 5 and not pyperclip.paste().startswith('<html') and not pyperclip.paste().startswith('<!--'):
            pyautogui.hotkey('ctrl', 'c')
            tries += 1

        tries = 0
        while tries < 10 and not pyperclip.paste().startswith('<html'):
            pyautogui.typewrite(['down'])
            pyautogui.hotkey('ctrl', 'c')
            tries += 1

        if pyperclip.paste().find('<title>New Tab</title>') != -1:
            print('ERROR: Got BLANK TAB')
            return

        with open(f'{CACHE_DIR}/website_{surl}.html', 'w', encoding='utf-8') as f:
            f.write(pyperclip.paste())

    def analyze_website(self, url: str, depth: int = 0):
        # pylint: disable=R0912,R0915
        domain = url_domain(url)
        surl = safe_url_key(url)

        if surl in self.results or url.find('<html') != -1:
            return

        print('AN:', len(self.results), url)
        with open(f'{CACHE_DIR}/website_{surl}.html', 'r', encoding='utf-8') as f:
            min_html = f.read().replace('\n', '').replace(' ', '')

        links_unfiltered = regex_find(r'href="(.*?)"', min_html)
        links = []
        statics = []
        domains = []
        contact = []
        for l in links_unfiltered:
            if l in ('/', '//'):
                continue

            if l.startswith('//'):
                l = l[2:]

            skip = False
            for b in LINK_IGNORE_BEG:
                if l.find(b) != -1:
                    skip = True
                    break

            for b in LINK_CONTACT_BEG:
                if l.find(b) != -1:
                    contact.append(l)
                    skip = True
                    break

            if skip:
                continue

            if l.find('://') == -1 and (not valid_domain(l) or l.endswith('.html')):
                if l.startswith('/'):
                    l = f'{domain}{l}'

                else:
                    l = f'{domain}/{l}'

            skip = False
            for e in LINK_STATICS_EXT:
                if l.find(f'.{e}') != -1:
                    domains.append(url_domain(l))
                    statics.append(l)
                    skip = True
                    break

            if skip:
                continue

            domains.append(url_domain(l))
            links.append(l)

        links = list(set(links))
        domains = list(set(domains))
        statics = list(set(statics))
        contact = list(set(contact))
        links.sort()
        domains.sort()
        statics.sort()
        contact.sort()

        self.results[surl] = {
            'urls': links,
            'domains': domains,
            'statics': statics,
            'contact': contact,
        }

        if depth < MAX_RECURSION:
            for l in links:
                if allow_follow(l):
                    skip = False
                    for p in LINK_PART_NO_FOLLOW:
                        if l.find(p) != -1:
                            skip = True
                            break

                    if skip:
                        continue

                    self.download_website(l)
                    self.analyze_website(l, depth=depth + 1)


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
    parser.add_argument('-t', '--target', help='Target domain or URL to scan', required=True)
    parser.add_argument('-f', '--follow', help='Domains or part of URLs to follow in recursive scan (comma-separated)', default='')
    parser.add_argument('-l', '--load-time', help='Time in seconds you want to wait for each page to load', default=2.0, type=float)
    parser.add_argument('-r', '--recursion-depth', help='Max depth of recursion', default=3, type=int)
    parser.add_argument('-s', '--skip', help='Skip scan if a part of the url matches one of these (comma-separated)', default='', type=str)

    args = parser.parse_args()

    TARGET = args.target
    TARGET_BASE = url_domain(TARGET).rsplit('.', 1)[0]

    if len(args.follow.strip()) == 0:
        FOLLOW_ALLOW_OTHER_LIST = []

    elif args.follow.find(',') != -1:
        FOLLOW_ALLOW_OTHER_LIST = args.follow.split(',')

    else:
        FOLLOW_ALLOW_OTHER_LIST = [args.follow]

    if args.skip.find(',') != -1:
        LINK_PART_NO_FOLLOW.extend(args.skip.split(','))

    elif len(args.skip.strip()) > 0:
        LINK_PART_NO_FOLLOW.append(args.skip)

    CACHE_DIR = f'{BASE_DIR}/cache/{safe_url_key(TARGET)}'
    MAX_RECURSION = args.recursion_depth
    PAGE_LOAD_WAIT = args.load_time

    WebCrawlerRecon().run()
