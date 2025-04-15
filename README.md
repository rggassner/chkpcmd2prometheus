# ASG Metrics Exporter

This script is a **Prometheus exporter** that collects performance and connection metrics from multiple ASG (Application Security Gateway) devices over SSH and exposes them via an HTTP `/metrics` endpoint.

It parses the output of `asg perf -v -p` and `asg_conns` commands from each configured ASG, structures the metrics, and exposes them in a Prometheus-compatible format for scraping.

## Features

- SSH into multiple ASG appliances to collect metrics.
- Parses and exposes:
  - ASG connection table statistics (`asg_conns`)
  - Performance metrics (`asg perf -v -p`)
- Runs as a Flask HTTP server on port `9102`.
- Updates metrics every 60 seconds in the background.
- Exports detailed per-member, per-path, and summary metrics.

## Requirements

- Python 3.7+
- `paramiko`
- `flask`

## Installation

Create and activate a virtual environment:


```
python3 -m venv venv

source venv/bin/activate
```



Install dependencies:


`pip install -r requirements.txt`


## Usage

Start the script with:


`./venv/bin/python3 chkpcmd2prometheus.py`

It will begin polling all servers listed in `servers.txt`, collecting and caching metrics, and exposing them at:


`http://localhost:9102/metrics`

You can configure Prometheus to scrape this endpoint.

## servers.txt Format

Each line must contain exactly four comma-separated values:


`<ip_or_hostname>,<ssh_user>,<ssh_password>,<friendly_name>`

Example:

`192.168.1.10,admin,admin123,asg-1 192.168.1.11,admin,admin123,asg-2`

Invalid lines will be skipped.

## Exported Metrics

Metrics are exported with labels for:

-   `host`: IP or DNS of the ASG
    
-   `host_name`: Friendly name (from `servers.txt`)
    
-   `member`: Member identifier (e.g., `1_01`)
    
-   `path`: For per-path distribution metrics
    

Example metric names:

-   `c2p_asg_conns_fw1_vals`
    
-   `c2p_asg_perf_sgm_throughput`
    
-   `c2p_asg_perf_summary_acceleration_load_avg`
    
-   `c2p_asg_perf_path_connection_rate`
    

## Logs

Logs are printed to stdout for debugging purposes. You can adjust the logging level by changing this line:

`logging.basicConfig(level=logging.DEBUG)`

## Notes

-   Ensure the `asg` commands (`asg_conns`, `asg perf -v -p`) are available and return valid data on the remote devices.
    
-   The script will continue polling indefinitely, so it's recommended to run it under a process manager (e.g., `systemd`, `supervisord`, `tmux`, or `screen`) in production.
    

## License

MIT License



