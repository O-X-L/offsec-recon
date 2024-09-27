# DNS / Domain Recon

We want to gather information about existing domains and the services behind them.

The included wordlist was copied from: [theMiddleBlue/DNSenum](https://github.com/theMiddleBlue/DNSenum) 

## Usage

Requirements: `pip install -r requirements.txt`

```bash
python3 main.py <DOMAIN>

python3 main.py google.com
```

Filter results using `jq`:

```bash
# get a simple list of all domains
cat results_<DOMAIN>.json | jq 'keys | .[]'

# get all unique IPv4 addresses
cat results_<DOMAIN>.json | jq -r '.[] | .ip | .ip4 | .[]' | uniq

# get all IPv4 PTRs
cat results_<DOMAIN>.json | jq -r '.[] | .ptr | .ip4 | .[]' | uniq
```
