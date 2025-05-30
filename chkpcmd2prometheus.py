#!venv/bin/python3
import os
import signal
import sys
import asyncio
import re
import time
import logging
import threading
import tornado.ioloop
import tornado.web
import tornado.httpserver
import paramiko

# Constants
PID_FILE = "/tmp/chkpcmd2prometheus.pid"
SERVERS_FILE = "servers.txt"
CONNECTION_TIMEOUT = 30  # Timeout in seconds for SSH connections
metrics_cache = {}

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)


def read_servers(file_path):
    """Read server information from a text file."""
    servers = []
    try:
        with open(file_path) as f:
            for line in f:
                parts = line.strip().split(',')
                if len(parts) == 5:
                    servers.append((
                        parts[0],  # ip
                        parts[1],  # username
                        parts[2],  # password
                        parts[3],  # host_name
                        parts[4]   # cmdb_name
                    ))
    except FileNotFoundError:
        logging.error(f"Servers file {file_path} not found.")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Error reading servers file: {e}")
        sys.exit(1)

    if not servers:
        logging.warning("No servers defined in the servers file.")

    return servers


def parse_metric(value: str) -> float:
    """Convert metric values (K, M, G) to numerical values."""
    multipliers = {'K': 1e3, 'M': 1e6, 'G': 1e9}
    match = re.match(r"([\d\.]+)\s*([KMG]?)", value)
    if match:
        num, unit = match.groups()
        return float(num) * multipliers.get(unit, 1)
    try:
        return float(value)
    except ValueError:
        return 0


def get_asg_perf(host, user, password, cmdbname):
    """Collect ASG performance metrics via SSH."""
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
                host,
                username=user,
                password=password,
                timeout=CONNECTION_TIMEOUT)
        stdin, stdout, stderr = client.exec_command(
                "timeout 5 asg perf -v -p",
                bufsize=-1,
                timeout=CONNECTION_TIMEOUT,
                get_pty=True)
        output = stdout.read().decode().strip()
        client.close()
        logging.debug(f"Output from asg perf -v -p on {host}:\n{output}")

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
                        data[section]['Acceleration load avg'] = int(value.split('/')[0].strip().strip('%'))
                        data[section]['Acceleration load min'] = int(value.split('/')[1].strip().strip('%'))
                        data[section]['Acceleration load max'] = int(value.split('/')[2].strip().strip('%'))
                    elif key == 'Instances load (avg/min/max)':
                        data[section]['Instances load avg'] = int(value.split('/')[0].strip().strip('%'))
                        data[section]['Instances load min'] = int(value.split('/')[1].strip().strip('%'))
                        data[section]['Instances load max'] = int(value.split('/')[2].strip().strip('%'))
                    else:
                        data[section][key] = parse_metric(value.strip())

            elif section == "Per SGM Distribution" and sgm_section:
                parts = re.split(r"\|+", line)
                if len(parts) >= 9 and 'SGM' not in line and 'Total' not in line and 'Cores' not in line and 'usage' not in line:
                    discard, sgm_id, throughput, pkt_rate, conn_rate, conc_conn, accel, inst, mem = parts[:9]
                    accel_parts = accel.strip().split('/')
                    inst_parts = inst.strip().split('/')

                    data[section][sgm_id.strip()] = {
                        "Throughput": parse_metric(throughput.strip()),
                        "Packet rate": parse_metric(pkt_rate.strip()),
                        "Connection rate": parse_metric(conn_rate.strip()),
                        "Concurrent connections": parse_metric(conc_conn.strip()),
                        "Acceleration load avg": int(accel_parts[0].strip('%')) if len(accel_parts) > 0 else 0,
                        "Acceleration load min": int(accel_parts[1].strip('%')) if len(accel_parts) > 1 else 0,
                        "Acceleration load max": int(accel_parts[2].strip('%')) if len(accel_parts) > 2 else 0,
                        "Instances load avg": int(inst_parts[0].strip('%')) if len(inst_parts) > 0 else 0,
                        "Instances load min": int(inst_parts[1].strip('%')) if len(inst_parts) > 1 else 0,
                        "Instances load max": int(inst_parts[2].strip('%')) if len(inst_parts) > 2 else 0,
                        "Memory usage": parse_metric(mem.strip()),
                    }

            elif section == "Per Path Distribution":
                parts = [p.strip() for p in re.split(r"\|+", line) if p.strip()]  # Remove empty entries

                if len(parts) >= 2 and 'Acceleration' not in line:  # Adjust for missing Dropped values
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
    except Exception as e:
        logging.error(f"Error retrieving ASG performance metrics from {host}: {e}")
        return None


def get_asg_conns(host, user, password, cmdbname):
    """Collect ASG connection metrics via SSH."""
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, username=user, password=password, timeout=CONNECTION_TIMEOUT)
        stdin, stdout, stderr = client.exec_command("asg_conns", timeout=CONNECTION_TIMEOUT)
        output = stdout.read().decode().strip()
        client.close()
        logging.debug(f"Output from asg conns on {host}:\n{output}")

        metrics = {"members": {}}
        total_fw1_connections = 0
        total_securexl_connections = 0
        current_member = None

        lines = output.splitlines()
        for i, line in enumerate(lines):
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
                logging.debug(f"Parsed member {current_member}: VALS={vals}, PEAK={peak}, SLINKS={slinks}")

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
                    metrics["members"][current_member]["number_of_connections"] = int(match.group(1))
                    logging.debug(f"Parsed total connections for {current_member}: {metrics['members'][current_member]['number_of_connections']}")
        return metrics
    except Exception as e:
        logging.error(f"Error retrieving ASG connection metrics from {host}: {e}")
        return None

def get_asg_status(host, user, password, cmdbname):
    """Collect ASG status metrics via SSH by running 'asg stat -v'."""
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, username=user, password=password, timeout=CONNECTION_TIMEOUT)
        stdin, stdout, stderr = client.exec_command("asg stat -v", timeout=CONNECTION_TIMEOUT)
        output = stdout.read().decode().strip()
        client.close()
        logging.debug(f"Output from 'asg stat -v' on {host}:\n{output}")

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
                    logging.debug(f"Parsed SGM {sgm_id} status: {status}")

            # Synchronization status
            elif "Sync to Active chassis:" in line:
                parts = line.split(":")
                if len(parts) >= 2:
                    metrics["sync_status"] = parts[1].strip().strip("|").strip()
        return metrics

    except Exception as e:
        logging.error(f"Error retrieving ASG status metrics from {host}: {e}")
        return None

def format_metrics():
    """Format metrics into Prometheus exposition format."""
    results = []
    for host, metrics_data in metrics_cache.items():
        if "asg_conns" not in metrics_data:
            logging.warning(f"No ASG connection data for {host} {metrics_data['name']}")
            continue

        data = metrics_data["asg_conns"]
        if not data:
            logging.warning(f"Empty ASG connection data for {host} {metrics_data['name']}")
            continue

        # Connection metrics for each member
        for member, values in data["members"].items():
            results.append(f'c2p_asg_conns_fw1_vals{{host="{host}", host_name="{metrics_data["name"]}", cmdb_name="{metrics_data["cmdbname"]}", member="{member}"}} {values.get("vals", 0)}')
            results.append(f'c2p_asg_conns_fw1_peak{{host="{host}", host_name="{metrics_data["name"]}", cmdb_name="{metrics_data["cmdbname"]}", member="{member}"}} {values.get("peak", 0)}')
            results.append(f'c2p_asg_conns_fw1_slinks{{host="{host}", host_name="{metrics_data["name"]}", cmdb_name="{metrics_data["cmdbname"]}", member="{member}"}} {values.get("slinks", 0)}')
            results.append(f'c2p_asg_conns_sxl_connections{{host="{host}", host_name="{metrics_data["name"]}", cmdb_name="{metrics_data["cmdbname"]}", member="{member}"}} {values.get("number_of_connections", 0)}')

        # Total metrics
        results.append(f'c2p_asg_conns_fw1_total_connections{{host="{host}",host_name="{metrics_data["name"]}", cmdb_name="{metrics_data["cmdbname"]}"}} {data.get("fw1_connections_total", 0)}')
        results.append(f'c2p_asg_conns_sxl_total_connections{{host="{host}",host_name="{metrics_data["name"]}", cmdb_name="{metrics_data["cmdbname"]}"}} {data.get("securexl_connections_total", 0)}')

        # ASG Performance metrics
        if "asg_perf" in metrics_data:
            perf_data = metrics_data["asg_perf"]
            keys_to_check = ['Concurrent conn.', 'Connection rate', 'Packet rate', 'Throughput']
            if "Per Path Distribution" in perf_data:
                for key in keys_to_check:
                    if key in perf_data['Per Path Distribution']:
                        for path_type, value in perf_data['Per Path Distribution'][key].items():
                            index_name = key.replace(' ', '_').replace('.', '').lower()
                            results.append(f'c2p_asg_perf_path_{index_name}{{host="{host}", host_name="{metrics_data["name"]}", cmdb_name="{metrics_data["cmdbname"]}", path="{path_type}"}} {value}')

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
                            results.append(f'c2p_asg_perf_sgm_{index_name}{{host="{host}", host_name="{metrics_data["name"]}", cmdb_name="{metrics_data["cmdbname"]}", member="{member}"}} {values[key]}')

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
                        results.append(f'c2p_asg_perf_summary_{index_name}{{host="{host}", host_name="{metrics_data["name"]}", cmdb_name="{metrics_data["cmdbname"]}"}} {perf_data["Performance Summary"][key]}')

        # ASG Status metrics
        if "asg_status" in metrics_data:
            status_data = metrics_data["asg_status"]

            # uptime: raw string, optional to parse
            if "uptime" in status_data:
                uptime_str = status_data["uptime"]
                results.append(f'c2p_asg_status_uptime_info{{host="{host}", host_name="{metrics_data["name"]}", cmdb_name="{metrics_data["cmdbname"]}", uptime="{uptime_str}"}} 1')

            # sgms: parse "5 / 5"
            if "sgms" in status_data:
                try:
                    active, total = status_data["sgms"].split('/')
                    active = int(active.strip())
                    total = int(total.strip())
                    results.append(f'c2p_asg_status_sgms_active{{host="{host}", host_name="{metrics_data["name"]}", cmdb_name="{metrics_data["cmdbname"]}"}} {active}')
                    results.append(f'c2p_asg_status_sgms_total{{host="{host}", host_name="{metrics_data["name"]}", cmdb_name="{metrics_data["cmdbname"]}"}} {total}')
                except Exception as e:
                    logging.error(f"Error parsing sgms for {host}: {e}")

            # version
            if "version" in status_data:
                results.append(f'c2p_asg_status_version_info{{host="{host}", host_name="{metrics_data["name"]}", cmdb_name="{metrics_data["cmdbname"]}", version="{status_data["version"]}"}} 1')

            # sgm_status
            if "sgm_status" in status_data:
                for member_id, state in status_data["sgm_status"].items():
                    results.append(
                        f'c2p_asg_status{{host="{host}", host_name="{metrics_data["name"]}", cmdb_name="{metrics_data["cmdbname"]}", sgm_id="{member_id}", status="{state}"}} 1'
                    )
                    state_val = 1 if state.lower() == "active" else 0
                    results.append(
                        f'c2p_asg_status_active{{host="{host}", host_name="{metrics_data["name"]}", cmdb_name="{metrics_data["cmdbname"]}", sgm_id="{member_id}"}} {state_val}'
                    )

            # sync_status
            if "sync_status" in status_data:
                sync_val = 1 if status_data["sync_status"].lower() == "enabled" else 0
                results.append(f'c2p_asg_status_sync_to_active{{host="{host}", host_name="{metrics_data["name"]}", cmdb_name="{metrics_data["cmdbname"]}"}} {sync_val}')

    return "\n".join(results)


def update_metrics_loop(servers):
    """Background thread to periodically update metrics."""
    global metrics_cache

    while True:
        new_metrics = {}
        for host, user, password, hostname, cmdbname in servers:
            metrics_data = {}
            logging.info(f"Collecting metrics from {hostname} ({host})")

            # Collect ASG connections metrics
            asg_conns = get_asg_conns(host, user, password, cmdbname)
            if asg_conns:
                metrics_data["asg_conns"] = asg_conns
                logging.info(f"Successfully collected ASG connection metrics from {hostname}")
            else:
                logging.warning(f"Failed to collect ASG connection metrics from {hostname}")

            # Collect ASG performance metrics
            asg_perf = get_asg_perf(host, user, password, cmdbname)
            if asg_perf:
                metrics_data["asg_perf"] = asg_perf
                logging.info(f"Successfully collected ASG performance metrics from {hostname}")
            else:
                logging.warning(f"Failed to collect ASG performance metrics from {hostname}")

            # Collect ASG performance metrics
            asg_status = get_asg_status(host, user, password, cmdbname)
            if asg_status:
                metrics_data["asg_status"] = asg_status
                logging.info(f"Successfully collected ASG performance metrics from {hostname}")
            else:
                logging.warning(f"Failed to collect ASG performance metrics from {hostname}")

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
    """Tornado request handler for /metrics endpoint."""

    def get(self):
        """Handle GET requests to /metrics endpoint."""
        self.set_header("Content-Type", "text/plain")
        metrics_text = format_metrics()
        self.write(metrics_text)


def write_pid():
    """Write process ID to PID file."""
    if os.path.exists(PID_FILE):
        print("PID file exists. Is the exporter already running?")
        sys.exit(1)
    with open(PID_FILE, "w") as f:
        f.write(str(os.getpid()))


def remove_pid():
    """Remove PID file."""
    if os.path.exists(PID_FILE):
        os.remove(PID_FILE)


def signal_handler(signum, frame):
    """Handle termination signals."""
    print("Shutting down exporter...")
    remove_pid()
    sys.exit(0)


def main():
    """Main entry point."""
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
