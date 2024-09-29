# Website Link-Crawling Recon

We want to gather information about existing domains and the services behind them.

This script will drive a Chromium browser to access the target website and recursively all linked ones that are related. We chose to use an actual browser as this is the most stable and quiet way around anti-bot measurements. But it is also pretty slow.

## Usage

This script is only tested on Linux.

Install the Chromium Browser beforehand.

Requirements: `pip install -r requirements.txt`

```bash
python3 web_crawler/main.py -h
> usage: main.py [-h] -t TARGET [-f FOLLOW] [-l LOAD_TIME] [-r RECURSION_DEPTH]
> 
> options:
>   -h, --help            show this help message and exit
>   -t TARGET, --target TARGET
>                         Target domain or URL to scan
>   -f FOLLOW, --follow FOLLOW
>                         Domains or part of URLs to follow in recursive scan (comma-separated)
>   -l LOAD_TIME, --load-time LOAD_TIME
>                         Time in seconds you want to wait for each page to load
>   -r RECURSION_DEPTH, --recursion-depth RECURSION_DEPTH
>                         Max depth of recursion
>   -s SKIP, --skip SKIP  Skip scan if a part of the url matches one of these (comma-separated)

# example:
python3 web_crawler/main.py -t oxl.at
```

You might need to increase the `--load-time` if the website is on the slower side and download/copy-from-console does not work correctly.

The `--target` should be the website canonical domain. Else you might need to add a `--follow` argument. 

Filter results using `jq`:

```bash
# get all unique domains that are linked
cat web_crawler/out/results_<TARGET>.json | jq -r '.[] | .domains | .[]' |  sort | uniq

# get all unique urls that are linked
cat web_crawler/out/results_<TARGET>.json | jq -r '.[] | .urls | .[]' |  sort | uniq

# get all unique statics
cat web_crawler/out/results_<TARGET>.json | jq -r '.[] | .statics | .[]' |  sort | uniq

# get all unique contact links
cat web_crawler/out/results_<TARGET>.json | jq -r '.[] | .contact | .[]' |  sort | uniq
```

Note: Make sure the browser console is roughly this size - it might differ in your case:

<img src="https://raw.githubusercontent.com/O-X-L/offsec-recon/refs/heads/main/web_crawler/browser_console.webp" width="100%">

----

## Output

Example:

```json
{
    "www.oxl.at": {
        "urls": [
            "https://blog.o-x-l.at",
            "https://docs.o-x-l.at",
            "https://github.com/O-X-L",
            "https://github.com/O-X-L/cve-statistics",
            "https://ipinfo.io",
            "https://o-x-l.com",
            "https://status.oxl.at",
            "https://www.o-x-l.com",
            "https://www.oxl.at/",
            "https://www.youtube.com/@OXL-IT",
            "www.oxl.at/about-us",
            "www.oxl.at/automation",
            "www.oxl.at/contact",
            "www.oxl.at/impressum",
            "www.oxl.at/monitoring",
            "www.oxl.at/privacy",
            "www.oxl.at/security",
            "www.oxl.at/technology"
        ],
        "domains": [
            "blog.o-x-l.at",
            "docs.o-x-l.at",
            "files.oxl.at",
            "github.com",
            "ipinfo.io",
            "o-x-l.com",
            "status.oxl.at",
            "www.o-x-l.com",
            "www.oxl.at",
            "www.youtube.com"
        ],
        "statics": [
            "https://files.oxl.at/img/oxl3_sm.png",
            "www.oxl.at/css/content.css",
            "www.oxl.at/css/main.css",
            "www.oxl.at/css/noscript.css"
        ],
        "contact": []
    },
    "www.oxl.at_about-us": {
        "urls": [
            "https://at.linkedin.com/in/6abb7d37-42f3-4a21-af43-60bc25e91bf0",
            "https://blog.o-x-l.at",
            "https://docs.o-x-l.at",
            "https://github.com/O-X-L",
            "https://github.com/ansibleguy",
            "https://github.com/superstes",
            "https://ipinfo.io",
            "https://maps.app.goo.gl/jeyoCXRFGPT6mHBj9",
            "https://o-x-l.com",
            "https://opensource.com/resources/what-open-source",
            "https://status.oxl.at",
            "https://www.heise.de/news/iX-Workshop-BCM-Notfallplanung-und-Notfalluebungen-9719318.html",
            "https://www.niceshops.com",
            "https://www.o-x-l.com/about-us",
            "https://www.oxl.at/",
            "https://www.youtube.com/@OXL-IT",
            "www.oxl.at/about-us",
            "www.oxl.at/contact",
            "www.oxl.at/impressum",
            "www.oxl.at/privacy",
            "www.oxl.at/technology"
        ],
        "domains": [
            "at.linkedin.com",
            "blog.o-x-l.at",
            "docs.o-x-l.at",
            "files.oxl.at",
            "github.com",
            "ipinfo.io",
            "maps.app.goo.gl",
            "o-x-l.com",
            "opensource.com",
            "status.oxl.at",
            "www.heise.de",
            "www.niceshops.com",
            "www.o-x-l.com",
            "www.oxl.at",
            "www.youtube.com"
        ],
        "statics": [
            "https://files.oxl.at/certs/rath/barracuda_2018_engineer.pdf",
            "https://files.oxl.at/certs/rath/barracuda_2024_cgfw_foundation.pdf",
            "https://files.oxl.at/certs/rath/pve_2024_advanced_training.pdf",
            "https://files.oxl.at/certs/rath/sonicwall_2020_professional.pdf",
            "https://files.oxl.at/img/oxl3_sm.png",
            "www.oxl.at/css/content.css",
            "www.oxl.at/css/main.css",
            "www.oxl.at/css/noscript.css"
        ],
        "contact": []
    },
    "www.oxl.at_contact": {
        "urls": [
            "https://blog.o-x-l.at",
            "https://docs.o-x-l.at",
            "https://github.com/O-X-L",
            "https://ipinfo.io",
            "https://o-x-l.com",
            "https://status.oxl.at",
            "https://www.o-x-l.com/contact",
            "https://www.oxl.at/",
            "https://www.youtube.com/@OXL-IT",
            "www.oxl.at/about-us",
            "www.oxl.at/contact",
            "www.oxl.at/impressum",
            "www.oxl.at/privacy",
            "www.oxl.at/technology"
        ],
        "domains": [
            "blog.o-x-l.at",
            "docs.o-x-l.at",
            "files.oxl.at",
            "github.com",
            "ipinfo.io",
            "o-x-l.com",
            "status.oxl.at",
            "www.o-x-l.com",
            "www.oxl.at",
            "www.youtube.com"
        ],
        "statics": [
            "https://files.oxl.at/img/oxl3_sm.png",
            "www.oxl.at/css/main.css",
            "www.oxl.at/css/noscript.css",
            "www.oxl.at/css/single.css"
        ],
        "contact": [
            "mailto:kontakt@oxl.at",
            "tel:+43720302573"
        ]
    },
    "www.oxl.at_impressum": {
        "urls": [
            "http://www.ris.bka.gv.at/",
            "https://at.linkedin.com/in/6abb7d37-42f3-4a21-af43-60bc25e91bf0",
            "https://blog.o-x-l.at",
            "https://docs.o-x-l.at",
            "https://ec.europa.eu/consumers/odr/main/index.cfm?event=main.home2.show&amp;lng=DE",
            "https://firmen.wko.at/oxl-it-services-eu/steiermark/?firmaid=7992d30b-2bd0-47c2-ad7e-48d6c33563c8",
            "https://github.com/O-X-L",
            "https://ipinfo.io",
            "https://justizonline.gv.at/jop/web/firmenbuchabfrage/635245i_1",
            "https://o-x-l.com",
            "https://status.oxl.at",
            "https://www.o-x-l.com/impressum",
            "https://www.oxl.at/",
            "https://www.youtube.com/@OXL-IT",
            "www.oxl.at/about-us",
            "www.oxl.at/contact",
            "www.oxl.at/impressum",
            "www.oxl.at/privacy",
            "www.oxl.at/technology"
        ],
        "domains": [
            "at.linkedin.com",
            "blog.o-x-l.at",
            "docs.o-x-l.at",
            "ec.europa.eu",
            "files.oxl.at",
            "firmen.wko.at",
            "github.com",
            "ipinfo.io",
            "justizonline.gv.at",
            "o-x-l.com",
            "status.oxl.at",
            "www.o-x-l.com",
            "www.oxl.at",
            "www.ris.bka.gv.at",
            "www.youtube.com"
        ],
        "statics": [
            "https://files.oxl.at/img/oxl3_sm.png",
            "www.oxl.at/css/main.css",
            "www.oxl.at/css/noscript.css",
            "www.oxl.at/css/single.css"
        ],
        "contact": [
            "mailto:kontakt@oxl.at",
            "tel:+43720302573"
        ]
    },
    "www.oxl.at_privacy": {
        "urls": [
            "https://blog.o-x-l.at",
            "https://docs.o-x-l.at",
            "https://gdpr-info.eu/art-28-gdpr/",
            "https://gdpr-info.eu/art-6-gdpr/",
            "https://github.com/O-X-L",
            "https://ipinfo.io",
            "https://o-x-l.com",
            "https://status.oxl.at",
            "https://www.hetzner.com/legal/privacy-policy",
            "https://www.o-x-l.com/privacy",
            "https://www.oxl.at/",
            "https://www.youtube.com/@OXL-IT",
            "www.oxl.at/about-us",
            "www.oxl.at/contact",
            "www.oxl.at/impressum",
            "www.oxl.at/privacy",
            "www.oxl.at/technology"
        ],
        "domains": [
            "blog.o-x-l.at",
            "docs.o-x-l.at",
            "files.oxl.at",
            "gdpr-info.eu",
            "github.com",
            "ipinfo.io",
            "o-x-l.com",
            "status.oxl.at",
            "www.hetzner.com",
            "www.o-x-l.com",
            "www.oxl.at",
            "www.youtube.com"
        ],
        "statics": [
            "https://files.oxl.at/doc/OXL-IT-Services-Datenschutzerklaerung-DE.pdf",
            "https://files.oxl.at/img/oxl3_sm.png",
            "www.oxl.at/css/main.css",
            "www.oxl.at/css/noscript.css",
            "www.oxl.at/css/single.css"
        ],
        "contact": []
    }
}
```