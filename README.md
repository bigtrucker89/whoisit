# whoisit
Performs mass lookups of IPs and WHOIS records.  Will cache if lookup has happened within defined period of time and skip, and will also intelligently store whois data for network ranges and use that data to populate whois info, instead of looking up the same space for a new IP address.

| Argument      | Description                                                    |
| ------------- | -------------------------------------------------------------- |
| `input_file`  | Path to the input file containing IP addresses (one per line). |
| `output_file` | Path to the output file to store the results.                  |


| Option             | Description                                                              | Default          |
| ------------------ | ------------------------------------------------------------------------ | ---------------- |
| `--threads`        | Number of threads to use for parallel lookups.                           | `2 × CPU cores`  |
| `--throttle`       | Delay (in seconds) between WHOIS lookups to avoid rate limits.           | `1.0`            |
| `--format`         | Output format: either `csv` or `json`.                                   | `csv`            |
| `--filter-private` | Skip private and reserved IP addresses from processing.                  | (off by default) |
| `--max-cache-age`  | Age limit in hours for cache entries before they are considered expired. | `24`             |
| `--ignore-cache`   | Ignore all cached results and force fresh DNS and WHOIS lookups.         | (off by default) |

Example:

python lookup.py input.txt output.csv \
  --threads 8 \
  --throttle 2 \
  --format json \
  --filter-private \
  --max-cache-age 12 \
  --ignore-cache

