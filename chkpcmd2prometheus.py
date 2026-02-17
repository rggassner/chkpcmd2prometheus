#!venv/bin/python3
#pylint: disable=too-many-lines
"""
This script is designed to collect and expose various performance and
status metrics from ASG (Application Security Gateway) devices.

It performs the following key functions:
1. **Reads server configuration**: Loads server details (IP address, 
SSH login credentials, host name, etc.) from a file.
2. **Collects metrics**: Retrieves performance metrics, throughput data, 
ASG connection metrics, ASG status, and ASG performance data via SSH from the specified servers.
3. **Formats metrics**: Transforms the collected data into a
Prometheus-compatible format for monitoring and alerting.
4. **Exposes metrics**: Provides an HTTP endpoint (via Tornado web server)
that serves the metrics in a plain text format at `/metrics`.
5. **Runs in the background**: Continuously collects and updates metrics in
the background while exposing the data on a specific port (default is `9102`).
6. **Handles graceful shutdown**: Manages PID files and handles termination 
signals to ensure the script shuts down gracefully.

Modules and Libraries Used:
- **paramiko**: For SSH connections to retrieve data from the ASG devices.
- **tornado**: For setting up an HTTP server to expose the collected metrics to Prometheus.
- **logging**: For logging important events, warnings, and errors.
- **re**: For regular expressions to process and parse raw data.
- **os, sys, time, signal**: For system-related functionality like
handling process IDs (PID), shutdown signals, and delays.
- **threading**: For running the metrics collection process in a
separate thread, allowing continuous data collection without blocking the HTTP server.

Functions and Classes:
- `read_servers`: Reads and parses the configuration file to
load the list of servers.
- `get_performance_metrics`: Collects performance data from 
a specified ASG device using SSH.
- `get_throughput_metrics`: Collects throughput-related data from
a specified ASG device using SSH.
- `get_asg_perf`: Collects ASG performance data for version
`pre82` devices.
- `get_asg_conns`: Retrieves ASG connection metrics.
- `get_asg_status`: Collects ASG status information such as uptime,
version, and synchronization status.
- `parse_metric`: Parses a metric value and converts it into a
standard numeric format (handles units like K, M, G).
- `format_metrics`: Formats all collected metrics into
Prometheus-compatible text.
- `update_metrics_loop`: Continuously collects and updates metrics
from all defined servers.
- `MetricsHandler`: A Tornado HTTP request handler that serves
the metrics at `/metrics`.
- `write_pid`: Writes the process ID (PID) of the script to a file to
prevent multiple instances of the script from running.
- `remove_pid`: Removes the PID file during shutdown to clean up resources.
- `signal_handler`: Handles termination signals (SIGINT, SIGTERM)
to shut down the script gracefully.

This script is intended to run as a background service, continually
gathering ASG metrics and exposing them for monitoring purposes.

Usage:
1. Start the script: `python3 <script_name>.py`
2. Access the metrics at: `http://<host>:9102/metrics`
3. Configure Prometheus to scrape the metrics endpoint.
"""
import logging
import os
import signal
import sys
import re
import time
import threading
import tornado.ioloop
import tornado.web
import tornado.httpserver
import paramiko

logger = logging.getLogger(__name__)

# Constants
PID_FILE = "/tmp/chkpcmd2prometheus.pid"
SERVERS_FILE = "servers.txt"
CONNECTION_TIMEOUT = 30  # Timeout in seconds for SSH connections
metrics_cache = {}

# Configure logging
logging.basicConfig(
    #level=logging.DEBUG,
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)


def read_servers(file_path):
    """
    Reads and parses a list of servers from a CSV-style file.

    This function reads a file containing server information
    where each line represents a server's details. 
    The expected format is a comma-separated line with six fields:
        - IP address
        - Username for SSH login
        - Password for SSH login
        - Host name
        - CMDB name
        - Version of the ASG (e.g., "82" or "pre82")

    The function returns a list of tuples, each containing
    the server details, or exits the program if the file 
    cannot be read or is empty.

    Args:
        file_path (str): The path to the file containing server information.

    Returns:
        list: A list of tuples, where each tuple contains:
            - ip (str): IP address of the server.
            - username (str): SSH login username for the server.
            - password (str): SSH login password for the server.
            - host_name (str): Host name of the server.
            - cmdb_name (str): CMDB name associated with the server.
            - version (str): Version of the ASG (e.g., "82" or "pre82").

    Example:
        [
            ("192.168.1.1", "admin", "password123", "host1", "cmdb1", "82"),
            ("192.168.1.2", "user", "password456", "host2", "cmdb2", "pre82")
        ]

    Raises:
        SystemExit: If the file cannot be found or read, or if no servers are defined in the file.
    """
    servers = []
    try:
        with open(file_path) as f: #pylint: disable=unspecified-encoding
            for line in f:
                parts = line.strip().split(',')
                if len(parts) == 6:
                    servers.append((
                        parts[0],  # ip
                        parts[1],  # username
                        parts[2],  # password
                        parts[3],  # host_name
                        parts[4],  # cmdb_name
                        parts[5]  # version
                    ))
    except FileNotFoundError:
        logging.error("Servers file %s not found.", file_path)
        sys.exit(1)
    except Exception as e: #pylint: disable=broad-exception-caught
        logging.error("Error reading servers file: %s", e)
        sys.exit(1)

    if not servers:
        logging.warning("No servers defined in the servers file.")

    return servers


def get_performance_metrics(host, user, password): #pylint: disable=too-many-locals
    """
    Retrieves performance metrics from a remote ASG (Application Security Gateway) host.

    This function uses SSH to connect to the specified host
    and executes the `cluster-cli show info performance`
    command to gather a variety of performance metrics
    for the ASG members, including throughput, packet rate,
    connection rate, CPU usage, memory usage, and more.

    The function parses the output and returns a dictionary
    of performance metrics, including both total system-wide
    values as well as per-member metrics.

    Args:
        host (str): The IP address or hostname of the ASG.
        user (str): The username for SSH authentication.
        password (str): The password for SSH authentication.

    Returns:
        dict: A dictionary containing the parsed performance metrics. The structure includes:
            - member_id (str): A unique identifier for each member (e.g., "1_01").
                - throughput (float): Throughput value for the member.
                - packet_rate (float): Packet rate for the member.
                - connection_rate (float): Connection rate for the member.
                - concurrent_connections (float): Number of concurrent connections.
                - cpu_usage (float): CPU usage percentage.
                - fw_usage (float): Firewall usage percentage.
                - memory_usage (float): Memory usage percentage.

    Example:
        {
            "1_01_throughput": 500000,
            "1_01_packet_rate": 10000,
            "1_01_connection_rate": 500,
            "1_01_concurrent_connections": 200,
            "1_01_cpu_usage": 25.0,
            "1_01_fw_usage": 15.0,
            "1_01_memory_usage": 70.0
        }

    Notes:
        - This function parses both total metrics (not associated
        with any member) and individual member metrics.
        - Metrics names are sanitized by replacing spaces and hyphens
        with underscores, and converting to lowercase.
        - If the output cannot be parsed or if there is an error in
        the SSH connection, the function returns `None`.

    Raises:
        Exception: If an error occurs during the SSH connection,
        command execution, or if the output cannot be parsed.
    """
    performance_data = {}

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, username=user, password=password, timeout=CONNECTION_TIMEOUT)

        # Run the 'cluster-cli show info performance' command
        _stdin, stdout, _stderr = client.exec_command(
                "cluster-cli show info performance", 
                timeout=CONNECTION_TIMEOUT
        )
        output = stdout.read().decode().strip()
        client.close()

        print(f"Output from 'cluster-cli show info performance' on {host}:\n{output}")  # Debug log

        lines = output.splitlines()

        # First, parse the total row (not associated with any member)
        for line in lines:
            parts = [p.strip() for p in line.split("│") if p.strip()]

            # Skip header lines and non-metric rows (like 'Name', 'Value', 'Total', etc.)
            if len(parts) != 2 or \
                    any(header in parts[0].lower() for header in [
                        'name',
                        'value',
                        'total'
                    ]
                ):
                #print(f"len parts {len(parts)} {line}")
                continue

            name, _value = parts
            name = name.replace(" ", "_").replace("-", "_").lower()  # Sanitize the metric name

        # Now, parse the individual member rows (with IDs like 1_01, 1_02, etc.)
        for line in lines:
            parts = [p.strip() for p in line.split("│") if p.strip()]

            # Skip header lines and rows that don't contain valid metrics
            if len(parts) != 9 or \
                    any(header in parts[0].lower() for header in [
                        'id',
                        'throughput',
                        'packet',
                        'conn.',
                        'cpu',
                        'fw/snd'
                    ]
                ):
                continue

            member_id = parts[0]
            throughput = parse_metric(parts[1])
            packet_rate = parse_metric(parts[2])
            connection_rate = parse_metric(parts[3])
            concurrent_connections = parse_metric(parts[4])
            cpu_usage = parse_metric(parts[5])
            fw_usage = parse_metric(parts[7])
            memory_usage = parse_metric(parts[8])

            performance_data[f"{member_id}_throughput"] = throughput
            performance_data[f"{member_id}_packet_rate"] = packet_rate
            performance_data[f"{member_id}_connection_rate"] = connection_rate
            performance_data[f"{member_id}_concurrent_connections"] = concurrent_connections
            performance_data[f"{member_id}_cpu_usage"] = cpu_usage
            performance_data[f"{member_id}_fw_usage"] = fw_usage
            performance_data[f"{member_id}_memory_usage"] = memory_usage

        return performance_data
    except Exception as e: #pylint: disable=broad-exception-caught
        print(f"Error retrieving performance metrics from {host}: {e}")
        return None

def get_throughput_metrics(host, user, password): #pylint: disable=too-many-locals
    """
    Retrieves throughput metrics from a remote ASG (Application Security Gateway) host.

    This function uses SSH to connect to the specified host
    and executes the `cluster-cli show info throughput`
    command to gather throughput-related metrics, including:
    - Data throughput
    - Management throughput
    - Synchronization throughput

    The function parses the output and returns a dictionary of throughput metrics for each member.

    Args:
        host (str): The IP address or hostname of the ASG.
        user (str): The username for SSH authentication.
        password (str): The password for SSH authentication.
        cmdbname (str): The CMDB name associated with the ASG.

    Returns:
        dict: A dictionary containing the parsed throughput metrics. The structure includes:
            - member_id (str): A unique identifier for each member (e.g., "1_01").
                - "data" (int): Data throughput for the member.
                - "mgmt" (int): Management throughput for the member.
                - "sync" (int): Synchronization throughput for the member.

    Example:
        {
            "1_01": {
                "data": 1000000,
                "mgmt": 50000,
                "sync": 250000
            },
            "1_02": {
                "data": 1200000,
                "mgmt": 60000,
                "sync": 270000
            }
        }

    Raises:
        Exception: If an error occurs during the SSH connection or command execution,
        or if the output cannot be parsed.
    """
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, username=user, password=password, timeout=CONNECTION_TIMEOUT)

        # Run the 'cluster-cli show info throughput' command
        _stdin, stdout, _stderr = client.exec_command(
                "cluster-cli show info throughput",
                timeout=CONNECTION_TIMEOUT)
        output = stdout.read().decode().strip()
        client.close()
        logging.debug("Output from 'cluster-cli show info throughput' on %s:\n%s", host, output)
        throughput_data = {}

        # Parse the output: Skip the first two lines (headers), then process each member's data
        lines = output.splitlines()[2:]
        for line in lines:
            parts = [p.strip() for p in line.split("│") if p.strip()]
            if len(parts) >= 4:  # Ensure valid data
                member_id = parts[0]
                data = parse_metric(parts[1])
                mgmt = parse_metric(parts[2])
                sync = parse_metric(parts[3])

                # Store the metrics in a structured way
                throughput_data[member_id] = {
                    "data": int(data),
                    "mgmt": int(mgmt),
                    "sync": int(sync)
                }

        return throughput_data
    except Exception as e: #pylint: disable=broad-exception-caught
        logging.error("Error retrieving throughput metrics from %s: %s", host, e)
        return None


def parse_metric(value: str) -> float:
    """
    Parses a metric value represented as a string and converts it to a float.

    The function handles values with optional units (K, M, G) indicating multipliers
    for thousands, millions, and billions respectively. If no unit is provided, the value is
    parsed directly as a float. The function supports values with decimal points as well.

    Args:
        value (str): The metric value to parse, which may include a numerical value
        followed by a unit (e.g., "2.5M", "100K", "1500").

    Returns:
        float: The parsed numeric value of the metric, accounting for
        any unit multipliers (K = 1e3, M = 1e6, G = 1e9).
              If the value cannot be parsed, returns 0.

    Example:
        parse_metric("2.5M") -> 2500000.0
        parse_metric("100K") -> 100000.0
        parse_metric("1500") -> 1500.0
        parse_metric("1G") -> 1000000000.0

    Notes:
        - The function only supports the units 'K', 'M', and 'G'.
        - If the value cannot be parsed or is not in the expected format, it returns 0.

    Raises:
        ValueError: If the input string cannot be parsed into a valid number (e.g., "abc").
    """
    print(f"Parsing value: {value}")  # Debug log
    multipliers = {'K': 1e3, 'M': 1e6, 'G': 1e9}
    match = re.match(r"([\d\.]+)\s*([KMG]?)", value)
    if match:
        num, unit = match.groups()
        print(f"Matched number: {num}, unit: {unit}")  # Debug log
        return float(num) * multipliers.get(unit, 1)

    try:
        # If no unit, just return the float value
        return float(value)
    except ValueError:
        print(f"Error parsing value: {value}")  # Debug log
        return 0

def get_asg_perf(host, user, password): #pylint: disable=too-many-statements,too-many-branches,too-many-locals
    """
    Retrieves ASG (Application Security Gateway) performance metrics from a remote host.

    This function uses SSH to connect to the specified host
    and runs the `asg perf -v -p` command to gather
    performance-related data, including:
    - Performance summary.
    - Per SGM (Security Gateway Module) distribution.
    - Per-path distribution.

    The function processes the output and returns a dictionary containing
    the parsed performance metrics.

    Args:
        host (str): The IP address or hostname of the ASG.
        user (str): The username for SSH authentication.
        password (str): The password for SSH authentication.

    Returns:
        dict: A dictionary containing the parsed ASG performance metrics. The structure includes:
            - 'Performance Summary' (dict): Key metrics acceleration, instances, and memory usage.
            - 'Per SGM Distribution' (dict): Metrics for each SGM.
            - 'Per Path Distribution' (dict): Metrics related to traffic paths.

    Example:
        {
            "Performance Summary": {
                "Acceleration load avg": 75,
                "Instances load avg": 60,
                "Memory usage": 2048
            },
            "Per SGM Distribution": {
                "1_01": {
                    "Throughput": 1000,
                    "Packet rate": 5000,
                    "Concurrent connections": 1500
                },
                "1_02": {
                    "Throughput": 800,
                    "Packet rate": 4000,
                    "Concurrent connections": 1300
                }
            },
            "Per Path Distribution": {
                "Path1": {
                    "Acceleration": 95,
                    "Medium": 80,
                    "Firewall": 70,
                    "Dropped": 10
                }
            }
        }

    Raises:
        Exception: If an error occurs during the SSH connection or command execution.
    """
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
                host,
                username=user,
                password=password,
                timeout=CONNECTION_TIMEOUT)
        _stdin, stdout, _stderr = client.exec_command(
                "timeout 5 asg perf -v -p",
                bufsize=-1,
                timeout=CONNECTION_TIMEOUT,
                get_pty=True)
        output = stdout.read().decode().strip()
        client.close()
        logging.debug("Output from asg perf -v -p on %s:\n%s", host, output)

        data = {
            "Performance Summary": {},
            "Per SGM Distribution": {},
            "Per Path Distribution": {},
        }

        section = None
        sgm_section = False

        lines = output.splitlines()
        for line in lines:
            line = line.strip()
            if "Performance Summary" in line:
                section = "Performance Summary"
            elif "Per SGM Distribution Summary" in line:
                section = "Per SGM Distribution"
                sgm_section = True
            elif "Per Path Distribution Summary" in line:
                section = "Per Path Distribution"
                sgm_section = False
            elif not line or line.startswith("+") or line.startswith("*"):
                continue

            elif section == "Performance Summary":
                parts = re.split(r"\|+", line)
                if (
                        len(parts) >= 2
                        and 'Name' not in line
                        and 'Value' not in line
                        and 'IPv4' not in line
                ):
                    key, value = parts[1:3]
                    key = key.strip()
                    if key == 'Acceleration load (avg/min/max)':
                        data[section]['Acceleration load avg'] = \
                                int(value.split('/')[0].strip().strip('%'))
                        data[section]['Acceleration load min'] = \
                                int(value.split('/')[1].strip().strip('%'))
                        data[section]['Acceleration load max'] = \
                                int(value.split('/')[2].strip().strip('%'))
                    elif key == 'Instances load (avg/min/max)':
                        data[section]['Instances load avg'] = \
                                int(value.split('/')[0].strip().strip('%'))
                        data[section]['Instances load min'] = \
                                int(value.split('/')[1].strip().strip('%'))
                        data[section]['Instances load max'] = \
                                int(value.split('/')[2].strip().strip('%'))
                    else:
                        data[section][key] = parse_metric(value.strip())

            elif section == "Per SGM Distribution" and sgm_section:
                parts = re.split(r"\|+", line)
                if len(parts) >= 9 and \
                        'SGM' not in line and \
                        'Total' not in line and \
                        'Cores' not in line and \
                        'usage' not in line:
                    _discard, sgm_id, throughput, pkt_rate, conn_rate = parts[:5]
                    conc_conn, accel, inst, mem = parts[5:9]
                    accel_parts = accel.strip().split('/')
                    inst_parts = inst.strip().split('/')

                    data[section][sgm_id.strip()] = {
                        "Throughput": parse_metric(throughput.strip()),
                        "Packet rate": parse_metric(pkt_rate.strip()),
                        "Connection rate": parse_metric(conn_rate.strip()),
                        "Concurrent connections": parse_metric(conc_conn.strip()),
                        "Acceleration load avg": int(accel_parts[0].strip('%')) \
                                if len(accel_parts) > 0 else 0,
                        "Acceleration load min": int(accel_parts[1].strip('%')) \
                                if len(accel_parts) > 1 else 0,
                        "Acceleration load max": int(accel_parts[2].strip('%')) \
                                if len(accel_parts) > 2 else 0,
                        "Instances load avg": int(inst_parts[0].strip('%')) \
                                if len(inst_parts) > 0 else 0,
                        "Instances load min": int(inst_parts[1].strip('%')) \
                                if len(inst_parts) > 1 else 0,
                        "Instances load max": int(inst_parts[2].strip('%')) \
                                if len(inst_parts) > 2 else 0,
                        "Memory usage": parse_metric(mem.strip()),
                    }

            elif section == "Per Path Distribution":
                # Remove empty entries
                parts = [p.strip() for p in re.split(r"\|+", line) if p.strip()]


                # Adjust for missing Dropped values
                if len(parts) >= 2 and 'Acceleration' not in line:
                    key = parts[0]
                    accel = parts[1] if len(parts) > 1 else '0'
                    medium = parts[2] if len(parts) > 2 else '0'
                    firewall = parts[3] if len(parts) > 3 else '0'
                    dropped = parts[4] if len(parts) > 4 else '0'  # Ensure 'Dropped' has a default

                    data[section][key] = {
                        "Acceleration": parse_metric(accel),
                        "Medium": parse_metric(medium),
                        "Firewall": parse_metric(firewall),
                        "Dropped": parse_metric(dropped),
                    }
        return data
    except Exception as e:#pylint: disable=broad-exception-caught
        logging.error("Error retrieving ASG performance metrics from %s: %s", host, e)
        return None


def get_asg_conns(host, user, password):#pylint: disable=too-many-locals
    """
    Retrieves ASG (Application Security Gateway) connection metrics from a remote host.

    This function uses SSH to connect to host and runs the `asg_conns` command to gather
    connection-related data, including:
    - Number of connections in various states (e.g., VALS, PEAK, SLINKS).
    - Total number of firewall (fw1) and SecureXL connections.

    The function processes the output and returns a dictionary containing the connection metrics.

    Args:
        host (str): The IP address or hostname of the ASG.
        user (str): The username for SSH authentication.
        password (str): The password for SSH authentication.

    Returns:
        dict: A dictionary containing the parsed ASG connection metrics. The structure includes:
            - 'fw1_connections_total' (int): Total number of firewall (fw1) connections.
            - 'securexl_connections_total' (int): Total number of SecureXL connections.
            - 'members' (dict): A dictionary of connection metrics for each member.
              Each member contains:
                - 'vals' (int): Number of active connections.
                - 'peak' (int): Peak number of connections.
                - 'slinks' (int): Number of synchronization links.
                - 'number_of_connections' (int): Total number of connections for the member.

    Example:
        {
            "fw1_connections_total": 1000,
            "securexl_connections_total": 500,
            "members": {
                "1_01": {"vals": 300, "peak": 500, "slinks": 100, "number_of_connections": 400},
                "1_02": {"vals": 200, "peak": 400, "slinks": 80, "number_of_connections": 300}
            }
        }

    Raises:
        Exception: If an error occurs during the SSH connection or command execution.
    """
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, username=user, password=password, timeout=CONNECTION_TIMEOUT)
        _stdin, stdout, _stderr = client.exec_command("asg_conns", timeout=CONNECTION_TIMEOUT)
        output = stdout.read().decode().strip()
        client.close()
        logging.debug("Output from asg conns on %s:\n%s", host, output)

        metrics = {"members": {}}
        total_fw1_connections = 0
        total_securexl_connections = 0
        current_member = None

        lines = output.splitlines()
        for _i, line in enumerate(lines):
            line = line.strip()

            # Match a member identifier (e.g., "1_01:")
            match_member = re.match(r"^(\d{1,2}_\d{2}):$", line)
            if match_member:
                current_member = match_member.group(1)
                if current_member not in metrics["members"]:
                    metrics["members"][current_member] = {}

            # Extract member metrics: VALS, PEAK, SLINKS
            elif current_member and re.match(r"^\d+\s+\d+\s+\d+$", line):
                vals, peak, slinks = map(int, line.split())
                metrics["members"][current_member].update({
                    "vals": vals,
                    "peak": peak,
                    "slinks": slinks
                })
                logging.debug(
                        "Parsed member %s: VALS=%s, PEAK=%s, SLINKS=%s",
                        current_member, vals, peak, slinks
                )

            # Extract "Total (fw1 connections table)"
            elif "Total (fw1 connections table)" in line:
                match = re.search(r" (\d+) connections", line)
                if match:
                    total_fw1_connections = int(match.group(1))
                    metrics["fw1_connections_total"] = total_fw1_connections

            # Extract "Total (SecureXL connections table)"
            elif "Total (SecureXL connections table)" in line:
                match = re.search(r" (\d+) connections", line)
                if match:
                    total_securexl_connections = int(match.group(1))
                    metrics["securexl_connections_total"] = total_securexl_connections

            # Extract "Total number of connections" for each member
            elif current_member and "Number of connections" in line:
                match = re.search(r"(\d+)", line)
                if match:
                    metrics["members"][current_member]["number_of_connections"] = \
                            int(match.group(1))
                    logging.debug(
                            "Parsed total connections for %s: %s",
                            current_member,
                            metrics['members'][current_member]['number_of_connections']
                    )
        return metrics
    except Exception as e: #pylint: disable=broad-exception-caught
        logging.error("Error retrieving ASG connection metrics from %s: %s", host, e)
        return None

def get_asg_status(host, user, password): #pylint: disable=too-many-branches,too-many-locals
    """
    Retrieves the status information of the ASG (Application Security Gateway) from a remote host.

    This function uses SSH to connect to the specified host and
    run the `asg stat -v` command to gather
    detailed status information about the ASG, including:
    - Uptime
    - SGMs (Security Gateway Modules)
    - Version
    - SGM status
    - Synchronization status

    The function processes the output and returns a dictionary containing the parsed status metrics.

    Args:
        host (str): The IP address or hostname of the ASG.
        user (str): The username for SSH authentication.
        password (str): The password for SSH authentication.

    Returns:
        dict: A dictionary containing the parsed ASG status metrics. Possible keys include:
            - 'uptime' (str): The uptime of the ASG.
            - 'sgms' (str): The number of active SGMs.
            - 'version' (str): The ASG version.
            - 'sgm_status' (dict): A dictionary mapping SGM IDs to their status
            - 'sync_status' (str): The synchronization status of the ASG 

    Example:
        {
            "uptime": "1 day, 2 hours",
            "sgms": "5 / 5",
            "version": "R80.40",
            "sgm_status": {
                "1_01": "active",
                "1_02": "standby"
            },
            "sync_status": "enabled"
        }

    Raises:
        Exception: If an error occurs during the SSH connection or command execution.
    """
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, username=user, password=password, timeout=CONNECTION_TIMEOUT)
        _stdin, stdout, _stderr = client.exec_command("asg stat -v", timeout=CONNECTION_TIMEOUT)
        output = stdout.read().decode().strip()
        client.close()
        logging.debug("Output from 'asg stat -v' on %s:\n%s", host, output)

        metrics = {
            "uptime": None,
            "sgms": None,
            "version": None,
            "sgm_status": {},
            "sync_status": None
        }

        lines = output.splitlines()

        for i, line in enumerate(lines):
            line = line.strip()

            # Uptime
            if line.startswith("| Up time"):
                parts = line.split("|")
                if len(parts) >= 3:
                    metrics["uptime"] = parts[2].strip()

            # SGMs
            elif line.startswith("| SGMs") and "Chassis Parameters" not in lines[i-1]:
                # Avoids matching Chassis Parameters SGMs
                parts = line.split("|")
                if len(parts) >= 3:
                    metrics["sgms"] = parts[2].strip()

            # Members
            elif line.startswith("| Members") and "Chassis Parameters" not in lines[i-1]:
                # Avoids matching Chassis Parameters Members
                parts = line.split("|")
                if len(parts) >= 3:
                    metrics["sgms"] = parts[2].strip()

            # Version
            elif line.startswith("| Version"):
                parts = line.split("|")
                if len(parts) >= 3:
                    metrics["version"] = parts[2].strip()

            # SGM ID Status section
            elif re.match(r"^\|\s*\d+\s+", line):
                # Strip outer pipes
                line_content = line.strip("|").strip()
                # Split by multiple spaces
                parts = re.split(r'\s{2,}', line_content)
                if len(parts) >= 2:
                    sgm_id = parts[0]
                    status = parts[1]
                    metrics["sgm_status"][sgm_id] = status
                    logging.debug("Parsed SGM %s status: %s", sgm_id, status)

            # Synchronization status
            elif "Sync to Active chassis:" in line or "Sync to Active site:" in line:
                parts = line.split(":")
                if len(parts) >= 2:
                    metrics["sync_status"] = parts[1].strip().strip("|").strip()
        return metrics

    except Exception as e: #pylint: disable=broad-exception-caught
        logging.error("Error retrieving ASG status metrics from %s: %s", host, e)
        return None

def format_metrics(): #pylint: disable=too-many-statements,too-many-branches,too-many-locals
    """
    Formats and returns the collected metrics in Prometheus text exposition format.

    This function iterates over the `metrics_cache`, which contains metrics data
    for all servers being monitored. It extracts various types of metrics, including:
    - Performance metrics (e.g., throughput, connection rate, memory usage)
    - ASG connection metrics (e.g., number of connections, peak values)
    - ASG performance metrics (e.g., acceleration load, memory usage)
    - ASG status metrics (e.g., uptime, SGMs, sync status)

    The function returns a string in Prometheus text format, where each metric is
    labeled with the server's details (host, host_name, cmdb_name) and its corresponding value.

    Warnings are logged if certain types of metrics (e.g., performance or ASG connection data)
    are missing or empty for any server.

    Returns:
        str: A string containing the formatted metrics in Prometheus text exposition format.
    """
    results = []
    for host, metrics_data in metrics_cache.items(): #pylint: disable=too-many-nested-blocks
        if "performance" in metrics_data:
            performance_data = metrics_data["performance"]
            for metric, value in performance_data.items():

                # This indicates a per-member metric (like 1_01, 1_02, etc.)
                if metric.startswith("1_"):
                    member_id = "_".join(metric.split("_")[:2])  # e.g., "1_01"

                    # Everything after the second underscore, e.g., "throughput"
                    metric_name = "_".join(metric.split("_")[2:])
                    results.append(
                            f'cluster_cli_show_info_performance_{metric_name}{{host="{host}", '
                            f'host_name="{metrics_data["name"]}", '
                            f'cmdb_name="{metrics_data["cmdbname"]}", '
                            f'member="{member_id}"}} '
                            f'{value}'
                    )
                else:
                    results.append(
                            f'cluster_cli_show_info_performance_{metric.lower()}{{host="{host}", '
                            f'host_name="{metrics_data["name"]}", '
                            f'cmdb_name="{metrics_data["cmdbname"]}"}} '
                            f'{value}'
                    )
        else:
            logging.warning("No performance data for host %s", host)

        if "asg_conns" not in metrics_data:
            logging.warning("No ASG connection data for %s %s", host, metrics_data['name'])
            continue

        data = metrics_data["asg_conns"]
        if not data:
            logging.warning("Empty ASG connection data for %s %s", host, metrics_data['name'])
            continue

        # Connection metrics for each member
        for member, values in data["members"].items():
            results.append(
                    f'c2p_asg_conns_fw1_vals{{host="{host}", '
                    f'host_name="{metrics_data["name"]}", '
                    f'cmdb_name="{metrics_data["cmdbname"]}", '
                    f'member="{member}"}} '
                    f'{values.get("vals", 0)}'
            )
            results.append(
                    f'c2p_asg_conns_fw1_peak{{host="{host}", '
                    f'host_name="{metrics_data["name"]}", '
                    f'cmdb_name="{metrics_data["cmdbname"]}", '
                    f'member="{member}"}} '
                    f'{values.get("peak", 0)}'
            )
            results.append(
                    f'c2p_asg_conns_fw1_slinks{{host="{host}", '
                    f'host_name="{metrics_data["name"]}", '
                    f'cmdb_name="{metrics_data["cmdbname"]}", '
                    f'member="{member}"}} '
                    f'{values.get("slinks", 0)}'
            )
            results.append(
                    f'c2p_asg_conns_sxl_connections{{host="{host}", '
                    f'host_name="{metrics_data["name"]}", '
                    f'cmdb_name="{metrics_data["cmdbname"]}", '
                    f'member="{member}"}} '
                    f'{values.get("number_of_connections", 0)}'
            )

        # Throughput metrics for version 82
        if "throughput" in metrics_data:
            throughput_data = metrics_data["throughput"]
            for member, values in throughput_data.items():
                results.append(
                        f'cluster_cli_show_info_throughput_data{{host="{host}", '
                        f'host_name="{metrics_data["name"]}", '
                        f'cmdb_name="{metrics_data["cmdbname"]}", '
                        f'member="{member}"}} {values["data"]}'
                )
                results.append(
                        f'cluster_cli_show_info_throughput_mgmt{{host="{host}", '
                        f'host_name="{metrics_data["name"]}", '
                        f'cmdb_name="{metrics_data["cmdbname"]}", '
                        f'member="{member}"}} {values["mgmt"]}'
                )
                results.append(
                        f'cluster_cli_show_info_throughput_sync{{host="{host}", '
                        f'host_name="{metrics_data["name"]}", '
                        f'cmdb_name="{metrics_data["cmdbname"]}", '
                        f'member="{member}"}} {values["sync"]}'
                )

        # Total metrics
        results.append(
                f'c2p_asg_conns_fw1_total_connections{{host="{host}",'
                f'host_name="{metrics_data["name"]}", '
                f'cmdb_name="{metrics_data["cmdbname"]}"}} '
                f'{data.get("fw1_connections_total", 0)}'
        )
        results.append(
                f'c2p_asg_conns_sxl_total_connections{{host="{host}",'
                f'host_name="{metrics_data["name"]}", '
                f'cmdb_name="{metrics_data["cmdbname"]}"}} '
                f'{data.get("securexl_connections_total", 0)}'
        )

        # ASG Performance metrics
        if "asg_perf" in metrics_data:
            perf_data = metrics_data["asg_perf"]
            keys_to_check = ['Concurrent conn.', 'Connection rate', 'Packet rate', 'Throughput']
            if "Per Path Distribution" in perf_data:
                for key in keys_to_check:
                    if key in perf_data['Per Path Distribution']:
                        for path_type, value in perf_data['Per Path Distribution'][key].items():
                            index_name = key.replace(' ', '_').replace('.', '').lower()
                            results.append(
                                    f'c2p_asg_perf_path_{index_name}{{host="{host}", '
                                    f'host_name="{metrics_data["name"]}", '
                                    f'cmdb_name="{metrics_data["cmdbname"]}", '
                                    f'path="{path_type}"}} {value}'
                            )

            if "Per SGM Distribution" in perf_data:
                keys_to_check = [
                    'Acceleration load avg', 'Acceleration load max', 'Acceleration load min',
                    'Concurrent connections', 'Connection rate', 'Instances load avg',
                    'Instances load max', 'Instances load min', 'Memory usage',
                    'Packet rate', 'Throughput'
                ]
                for member, values in perf_data['Per SGM Distribution'].items():
                    for key in keys_to_check:
                        if key in values:
                            index_name = key.replace(' ', '_').replace('.', '').lower()
                            results.append(
                                    f'c2p_asg_perf_sgm_{index_name}{{host="{host}", '
                                    f'host_name="{metrics_data["name"]}", '
                                    f'cmdb_name="{metrics_data["cmdbname"]}", '
                                    f'member="{member}"}} {values[key]}'
                            )

            if "Performance Summary" in perf_data:
                keys_to_check = [
                    'Acceleration load avg', 'Acceleration load max', 'Acceleration load min',
                    'Concurrent connections', 'Connection rate', 'Instances load avg',
                    'Instances load max', 'Instances load min', 'Load average',
                    'Memory usage', 'Packet rate', 'Throughput'
                ]
                for key in keys_to_check:
                    if key in perf_data['Performance Summary']:
                        index_name = key.replace(' ', '_').replace('.', '').lower()
                        results.append(
                                f'c2p_asg_perf_summary_{index_name}{{host="{host}", '
                                f'host_name="{metrics_data["name"]}", '
                                f'cmdb_name="{metrics_data["cmdbname"]}"}} '
                                f'{perf_data["Performance Summary"][key]}'
                        )

        # ASG Status metrics
        if "asg_status" in metrics_data:
            status_data = metrics_data["asg_status"]

            # uptime: raw string, optional to parse
            if "uptime" in status_data:
                uptime_str = status_data["uptime"]
                results.append(
                        f'c2p_asg_status_uptime_info{{host="{host}", '
                        f'host_name="{metrics_data["name"]}", '
                        f'cmdb_name="{metrics_data["cmdbname"]}", '
                        f'uptime="{uptime_str}"}} 1')

            # sgms: parse "5 / 5"
            if "sgms" in status_data:
                try:
                    active, total = status_data["sgms"].split('/')
                    active = int(active.strip())
                    total = int(total.strip())
                    results.append(
                            f'c2p_asg_status_sgms_active{{host="{host}", '
                            f'host_name="{metrics_data["name"]}", '
                            f'cmdb_name="{metrics_data["cmdbname"]}"}} {active}'
                    )
                    results.append(
                            f'c2p_asg_status_sgms_total{{host="{host}", '
                            f'host_name="{metrics_data["name"]}", '
                            f'cmdb_name="{metrics_data["cmdbname"]}"}} {total}'
                    )
                except Exception as e: #pylint: disable=broad-exception-caught
                    logging.error("Error parsing sgms for %s: %s", host, e)

            # version
            if "version" in status_data:
                results.append(
                        f'c2p_asg_status_version_info{{host="{host}", '
                        f'host_name="{metrics_data["name"]}", '
                        f'cmdb_name="{metrics_data["cmdbname"]}", '
                        f'version="{status_data["version"]}"}} 1'
                )

            # sgm_status
            if "sgm_status" in status_data:
                for member_id, state in status_data["sgm_status"].items():
                    results.append(
                        f'c2p_asg_status{{host="{host}", '
                        f'host_name="{metrics_data["name"]}", '
                        f'cmdb_name="{metrics_data["cmdbname"]}", '
                        f'sgm_id="{member_id}", status="{state}"}} 1'
                    )
                    state_val = 1 if state.lower() == "active" else 0
                    results.append(
                        f'c2p_asg_status_active{{host="{host}", '
                        f'host_name="{metrics_data["name"]}", '
                        f'cmdb_name="{metrics_data["cmdbname"]}", '
                        f'sgm_id="{member_id}"}} {state_val}'
                    )
            sync_status = status_data.get("sync_status")
            if sync_status is None:
                logger.warning("sync_status is None for host %s", host)
                sync_val = 0
            elif isinstance(sync_status, str):
                sync_val = 1 if sync_status.lower() == "enabled" else 0
                results.append(
                        f'c2p_asg_status_sync_to_active{{host="{host}", '
                        f'host_name="{metrics_data["name"]}", '
                        f'cmdb_name="{metrics_data["cmdbname"]}"}} '
                        f'{sync_val}'
                )
            else:
                logger.warning(
                        "Unexpected sync_status type %s for host %s",
                        type(sync_status),
                        host
                )
                sync_val = 0
    return "\n".join(results)


def update_metrics_loop(servers): #pylint: disable=too-many-branches
    """
    Periodically collects metrics from configured servers and updates the global metrics cache.

    This function runs in a separate background thread and performs the following tasks:
        1. Iterates over the list of servers, defined by `servers`, and collects metrics
           (e.g., ASG connection data, throughput, performance, status) via SSH.
        2. Collects metrics for each server by calling various helper functions like
           `get_asg_conns`, `get_throughput_metrics`, `get_performance_metrics`, etc.
        3. Updates the global `metrics_cache` with the collected data for each server.
        4. Waits for 60 seconds before starting the next metrics collection cycle.

    The function ensures that the exporter is continuously gathering fresh metrics
    from the servers and makes the most up-to-date data available for Prometheus scraping.

    Args:
        servers (list): A list of tuples, where each tuple contains the details for a server
                         (host, user, password, hostname, cmdbname, version).

    This function runs indefinitely and should be executed in a separate thread.
    """
    global metrics_cache #pylint: disable=global-statement

    while True:
        new_metrics = {}
        for host, user, password, hostname, cmdbname, version in servers:
            metrics_data = {}
            logging.info("Collecting metrics from %s (%s)", hostname, host)

            # Collect ASG connections metrics
            asg_conns = get_asg_conns(host, user, password)
            if asg_conns:
                metrics_data["asg_conns"] = asg_conns
                logging.info("Successfully collected ASG connection metrics from %s", hostname)
            else:
                logging.warning("Failed to collect ASG connection metrics from %s", hostname)

            # Collect throughput metrics for version 82
            if version == "82":
                throughput_data = get_throughput_metrics(host, user, password)
                if throughput_data:
                    metrics_data["throughput"] = throughput_data
                    logging.info("Successfully collected throughput metrics from %s", hostname)
                else:
                    logging.warning("Failed to collect throughput metrics from %s", hostname)
                # Collect performance metrics for version 82
                performance_data = get_performance_metrics(host, user, password)
                if performance_data:
                    metrics_data["performance"] = performance_data
                    logging.info("Successfully collected performance metrics from %s", hostname)
                else:
                    logging.warning("Failed to collect performance metrics from %s", hostname)

            # Collect ASG performance metrics - Available only in pre82
            if version == 'pre82':
                asg_perf = get_asg_perf(host, user, password)
                if asg_perf:
                    metrics_data["asg_perf"] = asg_perf
                    logging.info("Successfully collected ASG performance metrics from %s", hostname)
                else:
                    logging.warning("Failed to collect ASG performance metrics from %s", hostname)

            # Collect ASG performance metrics
            asg_status = get_asg_status(host, user, password)
            if asg_status:
                metrics_data["asg_status"] = asg_status
                logging.info("Successfully collected ASG performance metrics from %s", hostname)
            else:
                logging.warning("Failed to collect ASG performance metrics from %s", hostname)

            # Store metrics for the host
            metrics_data['name'] = hostname
            metrics_data['cmdbname'] = cmdbname
            new_metrics[host] = metrics_data

        # Update the global metrics cache atomically
        metrics_cache = new_metrics
        logging.info("Metrics cache updated successfully")

        # Wait for the next collection cycle
        time.sleep(60)


class MetricsHandler(tornado.web.RequestHandler):
    """
    A request handler for serving Prometheus metrics.

    This handler responds to HTTP GET requests at the `/metrics` endpoint.
    It fetches the latest collected metrics from the exporter and formats
    them in Prometheus' text exposition format, which can then be scraped
    by a Prometheus server.

    Methods:
        get: Handles GET requests to the `/metrics` endpoint.
              Sets the appropriate content type (`text/plain`) and writes
              the formatted metrics to the response body.
        
        data_received: No-op method required by Tornado for compatibility
                       with streaming requests. It is not used in this handler.

    """
    def get(self):
        """
        Handles GET requests to the `/metrics` endpoint.

        This method fetches the latest metrics, formats them in Prometheus
        text format, and returns them with the appropriate `Content-Type`
        header (`text/plain`), making the metrics available for Prometheus to scrape.

        """
        self.set_header("Content-Type", "text/plain")
        metrics_text = format_metrics()
        self.write(metrics_text)

    def data_received(self, chunk):
        """
        No-op method required by Tornado.

        This method is a placeholder for compatibility with Tornado's
        streaming capabilities, but it is not used in this handler.

        Args:
            chunk (bytes): The data chunk received. This is ignored in this implementation.
        """


def write_pid():
    """
    Creates or updates the PID file with the current process ID.

    This function checks if the PID file (defined by `PID_FILE`) already exists.
    If the file exists, it indicates that the exporter is already running, and
    the function will terminate the program with an error message and exit status 1.

    If the PID file does not exist, the function creates it and writes the current
    process ID (PID) to the file. This helps to ensure that only one instance
    of the exporter is running at any time.

    Exits the program if the PID file already exists, to prevent multiple instances
    from running simultaneously.

    Raises:
        SystemExit: If the PID file exists, indicating that the exporter is already running.
    """
    if os.path.exists(PID_FILE):
        print("PID file exists. Is the exporter already running?")
        sys.exit(1)
    with open(PID_FILE, "w") as f: #pylint: disable=unspecified-encoding
        f.write(str(os.getpid()))


def remove_pid():
    """
    Removes the PID file if it exists.

    This function checks if the PID file (defined by `PID_FILE`) exists on
    the filesystem. If it does, the file is deleted to clean up and allow
    for a fresh start of the exporter.

    The PID file typically indicates that the exporter is currently running,
    and its removal helps ensure that future instances of the exporter can
    start without issues related to existing PID files.

    Does nothing if the PID file does not exist.

    """
    if os.path.exists(PID_FILE):
        os.remove(PID_FILE)


def signal_handler(_signum, _frame):
    """
    Gracefully shuts down the exporter upon receiving a termination signal.

    This function is registered as a signal handler for SIGINT (Ctrl+C) and
    SIGTERM (termination request). When a signal is received, the function:

        1. Prints a shutdown message to the console.
        2. Removes the PID file to allow future restarts.
        3. Exits the program with a status code of 0, indicating a clean shutdown.

    Args:
        _signum (int): The signal number. Not used in this handler.
        _frame (signal frame): The current stack frame. Not used in this handler.
    """
    print("Shutting down exporter...")
    remove_pid()
    sys.exit(0)


def main():
    """
    Entry point for the chkpcmd2prometheus exporter.

    This function initializes and starts the Prometheus exporter service
    responsible for collecting Check Point cluster metrics over SSH and
    exposing them via an HTTP endpoint compatible with Prometheus scraping.

    Workflow:
        1. Reads server connection details from SERVERS_FILE.
        2. Validates that at least one server is configured.
        3. Creates a PID file to prevent multiple instances.
        4. Registers SIGINT and SIGTERM handlers for graceful shutdown.
        5. Starts a background daemon thread that periodically:
            - Connects to each configured server via SSH
            - Collects ASG, performance, throughput, and status metrics
            - Updates the global metrics cache atomically
        6. Launches a Tornado-based HTTP server on port 9102.
        7. Exposes collected metrics at the `/metrics` endpoint
           in Prometheus text exposition format.

    The exporter runs indefinitely until it receives a termination signal.
    On shutdown, the PID file is removed to ensure clean restarts.

    Raises:
        SystemExit: If no servers are defined or if a PID file already exists.
    """
    # Read server information from file
    servers = read_servers(SERVERS_FILE)
    if not servers:
        logging.error("No servers defined. Exiting.")
        sys.exit(1)

    # Write PID file
    write_pid()

    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Start the metrics collection thread
    collection_thread = threading.Thread(
        target=update_metrics_loop,
        args=(servers,),
        daemon=True
    )
    collection_thread.start()
    logging.info("Started metrics collection thread")

    # Set up Tornado web server
    app = tornado.web.Application([
        (r"/metrics", MetricsHandler),
    ])
    server = tornado.httpserver.HTTPServer(app)

    server.listen(9102)
    logging.info("Exporter running on port 9102")

    # Start the Tornado IO loop
    tornado.ioloop.IOLoop.current().start()


if __name__ == "__main__":
    main()
