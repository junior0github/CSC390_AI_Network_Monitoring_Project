# AI Network Monitoring Project

This repository contains an experimental AI-based IDS (Intrusion Detection System) that monitors Suricata and Zeek logs in real-time, extracts features, and flags anomalous network events using an IsolationForest model.

## Purpose

This project was created for a course project (CSC390) to demonstrate how ML techniques can be applied to network telemetry to detect anomalous behavior. The included script reads Suricata `eve.json` and Zeek `conn.log` / `dns.log`, extracts numeric features, runs an IsolationForest detector, and appends alerts to a CSV file.

## Files added / updated

- `ai_ids.py` — improved, more robust version of the IDS monitor with deterministic encoding and CLI options.
- `Dockerfile` — container image to run the monitor.
- `requirements.txt` — Python dependencies.
- `.dockerignore` — files to exclude from the Docker build.

## Quick start (local)

1. Install Python 3.11+ and create a virtual environment (recommended):

   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt

2. Run the monitor against your logs (use `--once` to run a single iteration and exit):

   python ai_ids.py --suricata /path/to/eve.json --zeek-conn /path/to/conn.log --zeek-dns /path/to/dns.log --alert ./alerts.csv

3. Alerts will be appended to `alerts.csv` with columns: timestamp,src_ip,dest_ip,src_port,dest_port,proto,anomaly

## Docker

Build the image:

   docker build -t ai-ids:latest .

Run the container (example mounting logs and output file):

   docker run --rm -v /var/log/suricata/eve.json:/var/log/suricata/eve.json:ro \
     -v /path/on/host/alerts.csv:/app/alerts.csv \
     ai-ids:latest --suricata /var/log/suricata/eve.json --alert /app/alerts.csv

If you also have Zeek logs:

   docker run --rm \
     -v /var/log/suricata/eve.json:/var/log/suricata/eve.json:ro \
     -v /var/log/zeek/conn.log:/home/cpe326/zeek_logs/conn.log:ro \
     -v /var/log/zeek/dns.log:/home/cpe326/zeek_logs/dns.log:ro \
     -v /path/on/host/alerts.csv:/app/alerts.csv \
     ai-ids:latest --suricata /var/log/suricata/eve.json --zeek-conn /home/cpe326/zeek_logs/conn.log --zeek-dns /home/cpe326/zeek_logs/dns.log --alert /app/alerts.csv

## Notes & testing

- The updated `ai_ids.py` performs deterministic encoding for IPs and protocols so repeated runs remain consistent.
- For quick testing you can create small sample log files (or use the `--once` flag) and inspect `alerts.csv`.
- The model needs multiple samples before it will be re-fitted; initial dummy data is provided on first run to avoid errors.

## Sample output

When suspicious events are found the script prints warnings and appends rows to the alert CSV. Example console output:

   2026-08-18 12:00:00, WARNING: 3 suspicious events detected at 2026-08-18 12:00:00

And `alerts.csv` will contain lines like:

   2026-08-18T11:59:58,10.0.0.5,93.184.216.34,34567,80,TCP,-1

## Next improvements (suggested)

- Persist LabelEncoders or mappings to keep encoding stable across restarts.
- Add unit tests and sample logs in `tests/` to make validation repeatable.
- Add a small web UI or REST endpoint to stream alerts instead of CSV.

If you'd like, I can also add example synthetic log files and a docker-compose setup for local end-to-end testing.
