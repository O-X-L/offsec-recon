#!/usr/bin/env python3

from sys import argv
from time import sleep
from subprocess import Popen as ProcessOpen
from re import sub as regex_replace
from re import findall as regex_find
from json import dumps as json_dumps
from pathlib import Path

import pyautogui
import pyperclip

pyautogui.FAILSAFE = True
pyautogui.PAUSE = 0.5

CHROMIUM_BIN = 'chromium-browser'
# NOTE: positions are optimized for full-hd screen
URL_BAR = (pyautogui.size()[0] / 3, 80)
CONSOLE_HTML = (1400, 170)
CONSOLE_HTML_CUT = (1480, 350)

LINK_IGNORE_EXT = ['css', 'js', 'woff', 'woff2', 'png', 'jpg', 'jpeg', 'webp']
MAX_RECURSION = 3
TARGET = argv[1]
FOLLOW_ALLOW_OTHER_LIST = argv[2].split(',') if len(argv) > 2 else []
BASE_DIR = Path(__file__).parent.resolve()


def safe_url(url: str) -> str:
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

    def run(self):
        with ProcessOpen([CHROMIUM_BIN, '--icognito', '--guest']):
            self._init_browser()
            self.download_website(TARGET)
            try:
                self.analyze_website(TARGET)

            except KeyboardInterrupt:
                print()
                print('WARNING: SCAN INTERRUPTED')

            self._save_results()
            print('DONE')

    def _save_results(self):
        print('SAVING INFORMATION')

        with open(f'{BASE_DIR}/out/results_{safe_url(TARGET)}.json', 'w', encoding='utf-8') as f:
            f.write(json_dumps(self.results, indent=4))

    @staticmethod
    def _init_browser() :
        sleep(2)

        input(
            'WAITING for you to MAXIMIZE THE BROWSER WINDOW..\n'
            'Press ENTER to continue\n'
        )
        # todo: was not able to hit the maximize button.. :(

        pyautogui.leftClick(URL_BAR[0], URL_BAR[1])  # get focus
        pyautogui.hotkey('f12')  # open dev console

    def download_website(self, url: str):
        surl = safe_url(url)
        if surl in self.results:
            return

        print('DOWNLOAD:', url)
        pyautogui.leftClick(URL_BAR[0], URL_BAR[1])
        pyperclip.copy(url)
        pyautogui.hotkey('ctrl', 'v')
        pyautogui.typewrite(['enter'])
        sleep(3)
        pyautogui.rightClick(CONSOLE_HTML[0], CONSOLE_HTML[1])
        pyautogui.leftClick(CONSOLE_HTML_CUT[0], CONSOLE_HTML_CUT[1])

        with open(f'{BASE_DIR}/cache/website_{surl}.html', 'w', encoding='utf-8') as f:
            f.write(pyperclip.paste())

    def analyze_website(self, url: str, depth: int = 0):
        domain = url_domain(url)
        surl = safe_url(url)

        if surl in self.results:
            return

        print('ANALYZE:', url)
        with open(f'{BASE_DIR}/cache/website_{surl}.html', 'r', encoding='utf-8') as f:
            min_html = f.read().replace('\n', '').replace(' ', '')

        links_unfiltered = regex_find(r'href="(.*?)"', min_html)
        links = []
        domains = []
        for l in links_unfiltered:
            if l.startswith('mailto:') or l.startswith('tel:') or l.startswith('#'):
                continue

            if l.find('://') == -1:
                l = f'{domain}/{l}'

            domains.append(url_domain(l))

            skip = False
            for ignore_ext in LINK_IGNORE_EXT:
                if l.endswith(f'.{ignore_ext}'):
                    skip = True
                    break

            if skip:
                continue

            links.append(l)

        self.results[surl] = {'urls': list(set(links)), 'domains': list(set(domains))}

        if depth < MAX_RECURSION:
            for l in links:
                if allow_follow(l):
                    self.download_website(l)
                    self.analyze_website(l, depth=depth + 1)


if __name__ == '__main__':
    TARGET_BASE = url_domain(TARGET).rsplit('.', 1)[0]
    WebCrawlerRecon().run()
