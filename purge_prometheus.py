#!/bin/bash
#for metric in $(curl -s http://localhost:9090/api/v1/label/__name__/values | jq -r '.data[]')
#do
#     echo "Deleting $metric"
#     curl -X POST http://localhost:9090/api/v1/admin/tsdb/delete_series        -d "match[]=$metric"        -d "end=2025-05-29T23:59:59Z"
#done
#curl -X POST 'http://localhost:9090/api/v1/admin/tsdb/clean_tombstones'

#!/bin/bash
# Calculate the date two weeks ago in the required format (YYYY-MM-DDTHH:MM:SSZ)
# Using `date` command for flexibility.
# This calculates two weeks ago from the current date and sets the time to 23:59:59Z
END_DATE=$(date -d "2 weeks ago" +"%Y-%m-%dT00:00:00Z")

echo "Purging metrics older than: $END_DATE"

# Define a list of metrics to *exclude* from purging
# These metrics will be skipped during the deletion process.
declare -a EXCLUDED_METRICS=(
	"c2p_asg_perf_summary_concurrent_connections"
	"c2p_asg_perf_summary_connection_rate"
	"c2p_asg_perf_summary_instances_load_avg"
	"c2p_asg_perf_summary_instances_load_max"
	"c2p_asg_perf_summary_instances_load_min"
	"c2p_asg_perf_summary_load_average"
	"c2p_asg_perf_summary_memory_usage"
	"c2p_asg_perf_summary_packet_rate"
	"c2p_asg_perf_summary_throughput"
	"cluster_cli_show_info_performance_total_throughput"
)

# Fetch all metric names
ALL_METRICS=$(curl -s http://localhost:9090/api/v1/label/__name__/values | jq -r '.data[]')

for metric in $ALL_METRICS; do
    EXCLUDE=false
    for excluded_metric in "${EXCLUDED_METRICS[@]}"; do
        if [[ "$metric" == "$excluded_metric" ]]; then
            echo "Skipping excluded metric: $metric"
            EXCLUDE=true
            break
        fi
    done

    if [ "$EXCLUDE" == false ]; then
        echo "Deleting $metric older than $END_DATE"
        curl -X POST http://localhost:9090/api/v1/admin/tsdb/delete_series \
            -d "match[]=$metric" \
            -d "end=$END_DATE"
    fi
done

echo "Cleaning tombstones..."
curl -X POST 'http://localhost:9090/api/v1/admin/tsdb/clean_tombstones'

echo "Purge script finished."


