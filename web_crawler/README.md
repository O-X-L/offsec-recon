# Website Link-Crawling Recon

We want to gather information about existing domains and the services behind them.

This script will drive a Chromium browser to access the target website and recursively all linked ones that are related. We chose to use an actual browser as this is the most stable and quiet way around anti-bot measurements. But it is also pretty slow.

## Usage

Requirements: `pip install -r requirements.txt`

```bash
python3 main.py <DOMAIN/URL> <DOMAINS-TO-FOLLOW-COMMA-SEPARATED>

# example:
python3 main.py oxl.at o-x-l,host-svc.com
```

Filter results using `jq`:

```bash
# get all unique domains that are linked
cat results_<DOMAIN>.json | jq -r '.[] | .domains | .[]' |  sort | uniq

# get all unique urls that are linked
cat results_<DOMAIN>.json | jq -r '.[] | .urls | .[]' |  sort | uniq
```

----

## Output

tbc
