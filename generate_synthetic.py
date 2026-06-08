"""
Generate a harder synthetic security dataset with the same schema.
Usage: python generate_synthetic.py [output_file]
"""

import json
import random
import sys
from datetime import datetime, timedelta

# Usage: python generate_synthetic.py [output_file] [seed]
# Omit seed for a different dataset each time

EVENT_TYPES = ["Authentication", "Privilege Operation", "Defense Evasion",
               "Data Access", "Exfiltration"]
KILL_CHAIN_ORDER = EVENT_TYPES  # already in kill chain order
ALERT_STYLES = ["raw_telemetry", "behavioral", "rules_based"]
ENTITY_TYPES = ["User", "Host", "File", "Process", "Domain", "NetworkConnection", "Database"]

# Name pools
FIRST_NAMES = ["James", "Maria", "Robert", "Linda", "David", "Sarah", "Michael", "Emma",
               "William", "Olivia", "John", "Sophia", "Richard", "Ava", "Thomas", "Mia",
               "Daniel", "Emily", "Paul", "Grace", "Kevin", "Chloe", "Brian", "Lily",
               "Andrew", "Zoe", "Steven", "Nora", "Peter", "Ella"]
LAST_NAMES = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller",
              "Davis", "Rodriguez", "Martinez", "Wilson", "Anderson", "Taylor", "Thomas",
              "Moore", "Jackson", "Martin", "Lee", "Clark", "Lewis"]
DOMAINS = [f"{''.join(random.choices('abcdefghijklmnop', k=random.randint(4,8)))}.{tld}"
           for tld in ["com", "net", "org", "io", "co"] for _ in range(10)]
PROCESSES = ["chrome.exe", "firefox.exe", "svchost.exe", "explorer.exe", "cmd.exe",
             "powershell.exe", "python.exe", "java.exe", "node.exe", "sqlservr.exe",
             "outlook.exe", "teams.exe", "code.exe", "notepad.exe", "msiexec.exe"]

ALERT_TEMPLATES = {
    "Authentication": [
        "Unusual login from {user} to {host} via {ip}",
        "Service account {user} authenticated interactively on {host}",
        "Multiple failed login attempts for {user} on {host} from {ip}",
        "Off-hours authentication by {user} on {host}",
    ],
    "Privilege Operation": [
        "Privilege escalation detected: {user} on {host}",
        "Admin rights granted to {user} on {host}",
        "Sudo/runas invocation by {user} on {host} running {proc}",
        "Sensitive group membership change for {user} on {host}",
    ],
    "Defense Evasion": [
        "Log clearing detected on {host} by {user}",
        "Security tool disabled on {host} by {proc}",
        "Timestomping detected on {file} on {host}",
        "Obfuscated script execution by {user} on {host}",
    ],
    "Data Access": [
        "Bulk file access by {user} on {host}: {file}",
        "Database query spike from {user} on {host}",
        "Sensitive document accessed: {file} by {user}",
        "Unusual data volume read by {user} from {host}",
    ],
    "Exfiltration": [
        "Large outbound transfer from {host} to {domain}",
        "Data exfiltration suspected: {user} uploading to {domain}",
        "Unusual DNS tunneling from {host} to {domain}",
        "Encrypted archive {file} sent externally by {user}",
    ],
}

# Counters for unique IDs
_counters = {"event": 0, "entity": 0, "rel": 0}

def make_id(kind):
    _counters[kind] += 1
    prefix = {"event": "EVT", "entity": "ENT", "rel": "REL"}[kind]
    return f"{prefix}-{_counters[kind]:04d}"

def make_entity(etype):
    eid = make_id("entity")
    if etype == "User":
        name = f"{random.choice(FIRST_NAMES)} {random.choice(LAST_NAMES)}"
    elif etype == "Host":
        prefix = random.choice(["WS", "SRV", "DC", "APP", "DB"])
        name = f"{prefix}-{random.randint(100, 999)}"
    elif etype == "File":
        ext = random.choice(["xlsx", "docx", "pdf", "csv", "zip", "vbs", "ps1", "exe", "dat"])
        name = f"{''.join(random.choices('abcdefghijklmnop', k=5))}{random.randint(1,99)}.{ext}"
    elif etype == "Process":
        name = random.choice(PROCESSES)
    elif etype == "Domain":
        name = random.choice(DOMAINS)
    elif etype == "NetworkConnection":
        name = f"192.168.{random.randint(1,254)}.{random.randint(1,254)}"
    elif etype == "Database":
        name = random.choice(["UserDB", "FinanceDB", "CustomerDB", "LogDB", "HRDatabase",
                              "InventoryDB", "AnalyticsDB", "AuthDB"])
    else:
        name = eid
    return {"id": eid, "type": etype, "name": name}

def make_event(etype, severity, alert_style, timestamp, entities_in_scope):
    eid = make_id("event")
    # Build alert message from template
    template = random.choice(ALERT_TEMPLATES[etype])
    fill = {}
    for e in entities_in_scope:
        key_map = {"User": "user", "Host": "host", "File": "file",
                   "Process": "proc", "Domain": "domain",
                   "NetworkConnection": "ip", "Database": "db"}
        key = key_map.get(e["type"])
        if key and key not in fill:
            fill[key] = e["name"]
    # Fill remaining placeholders with generic values
    for key in ["user", "host", "file", "proc", "domain", "ip", "db"]:
        if key not in fill:
            fill[key] = "unknown"
    try:
        msg = template.format(**fill)
    except KeyError:
        msg = f"{etype} alert on system"

    return {
        "id": eid,
        "type": etype,
        "timestamp": timestamp.isoformat(),
        "severity": severity,
        "alert_style": alert_style,
        "alert_message": msg,
        "description": f"{etype} event detected",
    }

def make_component(event_types, sev_range, weight_range, base_time, span_hours):
    """Generate a connected component with given characteristics."""
    n_events = len(event_types)
    events = []
    entities = []
    relationships = []

    # Create shared entities (what connects events in this component)
    # Every component has at least a shared user and host
    shared_user = make_entity("User")
    shared_host = make_entity("Host")
    entities.extend([shared_user, shared_host])

    # Create per-event entities
    per_event_entities = []
    for _ in range(n_events):
        extras = []
        # Each event gets 1-3 additional entities
        for _ in range(random.randint(1, 3)):
            etype = random.choice(["File", "Process", "Domain",
                                   "NetworkConnection", "Database"])
            extras.append(make_entity(etype))
        per_event_entities.append(extras)
        entities.extend(extras)

    # Create events in temporal order
    for i, etype in enumerate(event_types):
        t = base_time + timedelta(hours=span_hours * i / max(n_events - 1, 1))
        sev = random.randint(sev_range[0], sev_range[1])
        style = random.choice(ALERT_STYLES)
        relevant_entities = [shared_user, shared_host] + per_event_entities[i]
        evt = make_event(etype, sev, style, t, relevant_entities)
        events.append(evt)

        # Create relationships to entities
        for ent in relevant_entities:
            w = round(random.uniform(weight_range[0], weight_range[1]), 3)
            relationships.append({
                "id": make_id("rel"),
                "source": evt["id"],
                "target": ent["id"],
                "type": "related_to",
                "weight": w,
            })

    return events, entities, relationships


def generate_dataset():
    all_events = []
    all_entities = []
    all_relationships = []
    tp_event_ids = []
    tp_entity_ids = []
    attack_scenarios = []

    base_time = datetime(2025, 6, 1, 0, 0, 0)

    # --- TRUE POSITIVE COMPONENTS (6 attack scenarios) ---
    tp_configs = [
        # (description, event_types, sev_range, weight_range, span_hours)
        ("Supply Chain Attack",
         ["Authentication", "Privilege Operation", "Defense Evasion", "Data Access", "Exfiltration"],
         (6, 9), (0.78, 0.95), 8),
        ("Supply Chain Attack",
         ["Authentication", "Privilege Operation", "Defense Evasion", "Data Access", "Exfiltration"],
         (6, 9), (0.80, 0.93), 5),
        ("Supply Chain Attack",
         ["Authentication", "Authentication", "Privilege Operation", "Defense Evasion", "Data Access", "Exfiltration"],
         (5, 9), (0.75, 0.92), 10),
        ("Ransomware",
         ["Authentication", "Privilege Operation", "Data Access", "Exfiltration"],
         (7, 9), (0.82, 0.96), 3),
        ("Ransomware",
         ["Authentication", "Privilege Operation", "Defense Evasion", "Data Access", "Exfiltration"],
         (6, 8), (0.76, 0.90), 6),
        ("Ransomware",
         ["Authentication", "Defense Evasion", "Data Access", "Exfiltration"],
         (6, 9), (0.79, 0.94), 4),
    ]

    for i, (desc, etypes, sev_r, wt_r, span) in enumerate(tp_configs):
        t = base_time + timedelta(hours=random.uniform(0, 160))
        evts, ents, rels = make_component(etypes, sev_r, wt_r, t, span)
        all_events.extend(evts)
        all_entities.extend(ents)
        all_relationships.extend(rels)
        tp_event_ids.extend(e["id"] for e in evts)
        tp_entity_ids.extend(e["id"] for e in ents)
        attack_scenarios.append({
            "description": f"Attack Scenario: {desc}",
            "event_ids": [e["id"] for e in evts],
            "entity_ids": [e["id"] for e in ents],
        })

    # --- FALSE POSITIVE COMPONENTS ---
    # Easy FPs (majority): low severity, low weights, few stages
    for _ in range(140):
        n_events = random.randint(3, 8)
        # Pick 1-2 event types, repeated
        n_types = random.choice([1, 1, 1, 2, 2, 3])
        types_pool = random.sample(EVENT_TYPES, min(n_types, 5))
        etypes = [random.choice(types_pool) for _ in range(n_events)]
        t = base_time + timedelta(hours=random.uniform(0, 168))
        span = random.uniform(1, 24)
        evts, ents, rels = make_component(etypes, (1, 4), (0.25, 0.65), t, span)
        all_events.extend(evts)
        all_entities.extend(ents)
        all_relationships.extend(rels)

    # Medium FPs: higher severity OR higher weights, but not full kill chain
    for _ in range(25):
        n_events = random.randint(3, 8)
        n_types = random.choice([2, 3, 3])
        types_pool = random.sample(EVENT_TYPES, n_types)
        etypes = [random.choice(types_pool) for _ in range(n_events)]
        t = base_time + timedelta(hours=random.uniform(0, 168))
        span = random.uniform(2, 20)
        sev_r = random.choice([(3, 6), (4, 7), (2, 5)])
        wt_r = random.choice([(0.50, 0.78), (0.55, 0.82), (0.45, 0.75)])
        evts, ents, rels = make_component(etypes, sev_r, wt_r, t, span)
        all_events.extend(evts)
        all_entities.extend(ents)
        all_relationships.extend(rels)

    # Hard FPs: high kill chain coverage AND elevated severity/weights
    for _ in range(8):
        n_events = random.randint(5, 8)
        n_types = random.choice([4, 4, 5])
        types_pool = random.sample(EVENT_TYPES, n_types)
        etypes = [random.choice(types_pool) for _ in range(n_events)]
        random.shuffle(etypes)  # NOT in kill chain order (key difference from TP)
        t = base_time + timedelta(hours=random.uniform(0, 168))
        span = random.uniform(4, 24)
        sev_r = random.choice([(5, 8), (4, 7), (5, 7)])
        wt_r = random.choice([(0.65, 0.88), (0.70, 0.90), (0.60, 0.85)])
        evts, ents, rels = make_component(etypes, sev_r, wt_r, t, span)
        all_events.extend(evts)
        all_entities.extend(ents)
        all_relationships.extend(rels)

    # Assemble output
    dataset = {
        "metadata": {
            "source": "synthetic_generator",
            "generated_date": datetime.now().isoformat(),
            "time_range_start": base_time.isoformat(),
            "time_range_end": (base_time + timedelta(days=7)).isoformat(),
            "num_events": len(all_events),
            "num_entities": len(all_entities),
            "num_relationships": len(all_relationships),
            "num_true_positive_scenarios": len(attack_scenarios),
            "fp_tp_ratio": 20,
        },
        "events": all_events,
        "entities": all_entities,
        "relationships": all_relationships,
        "ground_truth": {
            "true_positive_events": tp_event_ids,
            "true_positive_entities": tp_entity_ids,
            "attack_scenarios": attack_scenarios,
            "fp_tp_ratio": 20,
        },
    }
    return dataset


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "synthetic_data.json"
    seed = int(sys.argv[2]) if len(sys.argv) > 2 else None
    random.seed(seed)
    data = generate_dataset()
    with open(out, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Generated: {data['metadata']['num_events']} events, "
          f"{data['metadata']['num_entities']} entities, "
          f"{data['metadata']['num_relationships']} relationships")
    print(f"TP events: {len(data['ground_truth']['true_positive_events'])}")
    print(f"Attack scenarios: {len(data['ground_truth']['attack_scenarios'])}")
    print(f"Saved to {out}")
