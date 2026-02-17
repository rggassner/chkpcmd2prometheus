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

# Prometheus Housekeeping Script


## Overview
This script is designed to help with the housekeeping tasks in Prometheus by purging older metrics data that is no longer needed, while preserving certain key metrics. It helps maintain the efficiency of the Prometheus server by reducing the size of the time-series database (TSDB), which can grow quickly due to large amounts of metrics data being scraped over time.

## Purpose
The primary purpose of this script is to purge metrics that are older than two weeks, helping to:
1. Free up disk space.
2. Improve query performance by reducing the amount of old data stored.
3. Ensure that only the most relevant and up-to-date metrics are kept.

## How It Works
1. **Define Purge Date**:
   - The script calculates the date two weeks ago (from the current date), setting the time to `00:00:00Z` on that day. This is done using the `date` command in a flexible and portable manner.

2. **Exclude Certain Metrics**:
   - A predefined list of metrics is excluded from the purging process. These metrics will not be deleted even if they are older than two weeks. This is useful for keeping important or critical metrics that are necessary for long-term monitoring.
   
3. **Fetch All Metrics**:
   - The script queries the Prometheus server at `http://localhost:9090/api/v1/label/__name__/values` to fetch a list of all metric names currently stored in the database.

4. **Purge Metrics**:
   - For each metric, the script checks if it is in the exclusion list. If not, it sends a `DELETE` request to the Prometheus API to remove the metric data older than the calculated date (`END_DATE`).

5. **Clean Tombstones**:
   - After the purging of metrics, the script sends a request to the Prometheus server to clean up "tombstones", which are markers for deleted data that may still occupy disk space.

## Excluded Metrics
The following metrics are **excluded** from purging and will not be deleted, regardless of their age:

- `c2p_asg_perf_summary_concurrent_connections`
- `c2p_asg_perf_summary_connection_rate`
- `c2p_asg_perf_summary_instances_load_avg`
- `c2p_asg_perf_summary_instances_load_max`
- `c2p_asg_perf_summary_instances_load_min`
- `c2p_asg_perf_summary_load_average`
- `c2p_asg_perf_summary_memory_usage`
- `c2p_asg_perf_summary_packet_rate`
- `c2p_asg_perf_summary_throughput`
- `cluster_cli_show_info_performance_total_throughput`
- `cluster_cli_show_info_performance_total_concurrent_connections`
- `cluster_cli_show_info_performance_total_connection_rate`
- `cluster_cli_show_info_performance_total_cpu_usage`
- `cluster_cli_show_info_performance_total_memory_usage`
- `cluster_cli_show_info_performance_total_packet_rate`

## Why is this Important for Prometheus Housekeeping?

Prometheus stores time-series data, and over time, this data can accumulate and take up a significant amount of disk space. If left unchecked, the Prometheus database can grow so large that it impacts performance, both for querying and for scraping new data. 

This script helps to automate the cleanup process by:
- **Removing old metrics** that are no longer useful (e.g., metrics from deprecated systems or features).
- **Reducing storage usage**, which ensures that Prometheus continues to operate efficiently.
- **Preserving important metrics** through the exclusion list, making sure that critical data isn't accidentally deleted.

By regularly running this script, you can ensure that your Prometheus instance remains fast, responsive, and cost-effective.

## How to Use

1. Modify the `EXCLUDED_METRICS` array to include any additional metrics you want to preserve.
2. Run the script periodically (e.g., using a cron job) to ensure your Prometheus server remains in good health.
   
```bash
# Example cron job to run the script every night at 2 AM
0 2 * * * /path/to/your/script.sh


## License

MIT License



