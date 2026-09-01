#!/usr/bin/env python3
"""
Build the labeled sample corpus.

Every event carries ground-truth labels so the harness can score detections:
    label     : "benign" | "malicious"
    episode   : attack id grouping one adversary sequence (null for benign)
    technique : MITRE ATT&CK id the event represents (null for benign)
    _logsource: "<product>/<service>" used to route events to matching rules

This is a *small, legible* stand-in so the repo runs out of the box. To scale
up, replace these files with real captures (see README): OTRF Security-Datasets
for host telemetry, flaws.cloud CloudTrail, or your own auth.log converted to
this shape. Keep the label/episode/technique fields and the rest of the harness
is unchanged.
"""

import json
from datetime import datetime, timedelta
from pathlib import Path

HERE = Path(__file__).parent
BASE = datetime(2024, 5, 1, 10, 0, 0)


def ts(offset_s: int) -> str:
    return (BASE + timedelta(seconds=offset_s)).strftime("%Y-%m-%dT%H:%M:%SZ")


def auth(offset, program, event_type, user, ip, label, episode=None, technique=None):
    return {
        "timestamp": ts(offset),
        "_logsource": "linux/auth",
        "program": program,
        "event_type": event_type,
        "user": user,
        "source_ip": ip,
        "label": label,
        "episode": episode,
        "technique": technique,
    }


def ct(offset, source, name, id_type, label, episode=None, technique=None,
       user=None, invoked_by=None, ip="198.51.100.9"):
    ev = {
        "timestamp": ts(offset),
        "_logsource": "aws/cloudtrail",
        "eventSource": source,
        "eventName": name,
        "userIdentity": {"type": id_type},
        "sourceIPAddress": ip,
        "awsRegion": "us-east-1",
        "label": label,
        "episode": episode,
        "technique": technique,
    }
    if user:
        ev["userIdentity"]["userName"] = user
    if invoked_by:
        ev["userIdentity"]["invokedBy"] = invoked_by
    return ev


auth_events = []

# --- malicious: SSH brute force episode 1 (203.0.113.7) -> detected on 5th fail
for i, off in enumerate([0, 9, 18, 27, 36, 45]):
    auth_events.append(
        auth(off, "sshd", "authentication_failure", "root", "203.0.113.7",
             "malicious", "ssh-bruteforce-01", "T1110.001")
    )

# --- malicious: SSH brute force episode 2 (198.51.100.23), starts +300s
for off in [300, 308, 316, 324, 332, 340, 348]:
    auth_events.append(
        auth(off, "sshd", "authentication_failure", "admin", "198.51.100.23",
             "malicious", "ssh-bruteforce-02", "T1110.001")
    )

# --- benign auth
auth_events += [
    auth(60, "sshd", "authentication_success", "alice", "10.0.0.5", "benign"),
    auth(120, "sshd", "authentication_failure", "bob", "192.0.2.11", "benign"),  # typo
    auth(125, "sshd", "authentication_success", "bob", "192.0.2.11", "benign"),
    # near-miss: 4 failures from one IP (below the gte:5 threshold -> must NOT fire)
    auth(180, "sshd", "authentication_failure", "svc", "192.0.2.50", "benign"),
    auth(190, "sshd", "authentication_failure", "svc", "192.0.2.50", "benign"),
    auth(200, "sshd", "authentication_failure", "svc", "192.0.2.50", "benign"),
    auth(210, "sshd", "authentication_failure", "svc", "192.0.2.50", "benign"),
    auth(900, "cron", "session_opened", "root", "127.0.0.1", "benign"),
    auth(1200, "sshd", "authentication_success", "alice", "10.0.0.5", "benign"),
    auth(1800, "sudo", "session_opened", "alice", "127.0.0.1", "benign"),
    auth(2700, "sshd", "authentication_success", "carol", "10.0.0.8", "benign"),
]

cloudtrail_events = [
    # --- malicious campaign: key creation -> recon -> disable logging (detected late)
    ct(600, "iam.amazonaws.com", "CreateAccessKey", "IAMUser", "malicious",
       "aws-campaign-01", "T1098", user="mallory", ip="203.0.113.7"),
    ct(630, "ec2.amazonaws.com", "DescribeInstances", "IAMUser", "malicious",
       "aws-campaign-01", "T1580", user="mallory", ip="203.0.113.7"),
    ct(720, "cloudtrail.amazonaws.com", "StopLogging", "IAMUser", "malicious",
       "aws-campaign-01", "T1562.008", user="mallory", ip="203.0.113.7"),

    # --- malicious: GuardDuty tampering (single-event, detected immediately)
    ct(840, "guardduty.amazonaws.com", "DeleteDetector", "IAMUser", "malicious",
       "aws-guardduty-01", "T1562.001", user="mallory", ip="203.0.113.7"),

    # --- malicious: root abuse (single-event, detected immediately)
    ct(960, "iam.amazonaws.com", "PutUserPolicy", "Root", "malicious",
       "aws-root-01", "T1078.004", ip="203.0.113.7"),

    # --- malicious: S3 exfiltration -> NO rule exists -> known coverage gap (miss)
    ct(1080, "s3.amazonaws.com", "GetObject", "IAMUser", "malicious",
       "aws-exfil-01", "T1530", user="mallory", ip="203.0.113.7"),
    ct(1085, "s3.amazonaws.com", "GetObject", "IAMUser", "malicious",
       "aws-exfil-01", "T1530", user="mallory", ip="203.0.113.7"),
    ct(1090, "s3.amazonaws.com", "GetObject", "IAMUser", "malicious",
       "aws-exfil-01", "T1530", user="mallory", ip="203.0.113.7"),

    # --- benign
    ct(660, "ec2.amazonaws.com", "DescribeInstances", "IAMUser", "benign",
       user="devops"),
    ct(690, "s3.amazonaws.com", "ListBuckets", "IAMUser", "benign", user="devops"),
    ct(780, "signin.amazonaws.com", "ConsoleLogin", "IAMUser", "benign",
       user="alice"),  # non-root login must not trip the root rule
    ct(1020, "cloudtrail.amazonaws.com", "DescribeTrails", "Root", "benign",
       invoked_by="AWS Internal"),  # AWS service event as root -> filtered
    ct(1500, "cloudtrail.amazonaws.com", "GetTrailStatus", "IAMUser", "benign",
       user="devops"),  # read-only, not a tampering verb
    ct(2400, "guardduty.amazonaws.com", "GetDetector", "IAMUser", "benign",
       user="secops"),  # read-only, not a tampering verb
    ct(3300, "s3.amazonaws.com", "GetObject", "IAMUser", "benign",
       user="analytics"),
]


def write(path: Path, rows):
    with path.open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    print(f"wrote {len(rows):>3} events -> {path.name}")


if __name__ == "__main__":
    write(HERE / "linux_auth.jsonl", auth_events)
    write(HERE / "aws_cloudtrail.jsonl", cloudtrail_events)
