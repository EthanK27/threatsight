import json
import time
import hashlib
from pathlib import Path
#you will need to change the name of the config uri to be able to work it with all the back end stuff
from pymongo import MongoClient, errors

INPUT_FILE = Path("/var/tmp/opencanary.log")
OUTPUT_FILE = Path("/home/honeypot/Desktop/normalized_events.jsonl")
POLL_INTERVAL = 0.2


MONGO_URI_FILE = Path(__file__).with_name("mongo_uri.py")

# Mongo target
MONGO_DB = "main"
MONGO_COLLECTION = "vulnhoneypots"


def classify_attack(dst_port):
    return {
        21: "ftp_login_attempt",
        22: "ssh_login_attempt",
        23: "telnet_login_attempt",
        80: "web_probe",
        443: "web_probe",
        3306: "mysql_probe",
        3389: "rdp_connection_attempt",
        445: "smb_probe",
        9418: "git_probe",
    }.get(dst_port, "unknown_activity")


def normalize(entry: dict) -> dict:
    dst_port = entry.get("dst_port")
    return {
        "timestamp": entry.get("utc_time")
        or entry.get("local_time_adjusted")
        or entry.get("local_time"),
        "src_ip": entry.get("src_host"),
        "src_port": entry.get("src_port"),
        "dst_ip": entry.get("dst_host"),
        "dst_port": dst_port,
        "attack_type": classify_attack(dst_port),
        "logtype": entry.get("logtype"),
    }


def compute_event_id(event: dict) -> str:
    """
    Stable-ish dedupe key based on the fields you already output.
    If the same line is processed twice, this will match and prevent duplicates (if you use upserts).
    """
    key = (
        f"{event.get('timestamp')}|{event.get('src_ip')}|{event.get('src_port')}|"
        f"{event.get('dst_ip')}|{event.get('dst_port')}|{event.get('attack_type')}|{event.get('logtype')}"
    )
    return hashlib.sha1(key.encode("utf-8", errors="ignore")).hexdigest()


def load_mongo_uri() -> str | None:
    if not MONGO_URI_FILE.exists():
        print(f"[!] Mongo URI file not found: {MONGO_URI_FILE} (Mongo upload disabled)")
        return None

    # Load a python file that defines MONGO_URI = "..."
    namespace = {}
    try:
        exec(MONGO_URI_FILE.read_text(encoding="utf-8"), namespace)
    except Exception as e:
        print(f"[!] Failed to read {MONGO_URI_FILE}: {e} (Mongo upload disabled)")
        return None

    uri = namespace.get("MONGO_URI")
    if not uri or not isinstance(uri, str):
        print(f"[!] {MONGO_URI_FILE} must define MONGO_URI = \"...\" (Mongo upload disabled)")
        return None

    return uri


def get_mongo_collection(uri: str):
    """
    Connect to Mongo and return a collection handle.
    Safe to call again if the connection drops.
    """
    client = MongoClient(uri, serverSelectionTimeoutMS=3000)

    # Force a quick connectivity check
    client.admin.command("ping")

    db = client[MONGO_DB]
    col = db[MONGO_COLLECTION]

    
    try:
        col.create_index("event_id", unique=True)
    except Exception:
        # If permissions disallow index creation, script still works (just no dedupe).
        pass

    return client, col


def mongo_upsert_event(col, event: dict) -> None:
    """
    Append-only behavior with dedupe:
    - If event_id is new: insert
    - If event_id already exists: do nothing (keeps older data)
    """
    col.update_one(
        {"event_id": event["event_id"]},
        {"$setOnInsert": event},
        upsert=True,
    )


def main():
    print("[*] Stripper started")
    print(f"[*] Watching: {INPUT_FILE}")
    print(f"[*] Writing:  {OUTPUT_FILE}")

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    while not INPUT_FILE.exists():
        print(f"[!] Waiting for logfile: {INPUT_FILE}")
        time.sleep(1)

    mongo_uri = load_mongo_uri()
    mongo_client = None
    mongo_col = None
    mongo_enabled = mongo_uri is not None

    if mongo_enabled:
        try:
            mongo_client, mongo_col = get_mongo_collection(mongo_uri)
            print(f"[*] Mongo enabled: db={MONGO_DB} collection={MONGO_COLLECTION}")
        except Exception as e:
            print(f"[!] Mongo connect failed: {e} (will retry on next event)")
            mongo_client, mongo_col = None, None

    with INPUT_FILE.open("r", encoding="utf-8", errors="replace") as log_file, \
         OUTPUT_FILE.open("a", encoding="utf-8") as out_file:

        log_file.seek(0, 2)  # start at end

        while True:
            line = log_file.readline()
            if not line:
                time.sleep(POLL_INTERVAL)
                continue

            line = line.strip()
            if not line:
                continue

           
            print("[RAW]", line)

            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue

            event = normalize(raw)

            # skip startup noise
            if not event["dst_port"] or not event["dst_ip"]:
                continue

           
            event["event_id"] = compute_event_id(event)

            out_file.write(json.dumps(event) + "\n")
            out_file.flush()

            
            if mongo_enabled:
                try:
                    if mongo_col is None:
                        mongo_client, mongo_col = get_mongo_collection(mongo_uri)
                        print("[*] Mongo reconnected")

                    mongo_upsert_event(mongo_col, event)

                except errors.DuplicateKeyError:
                    
                    pass
                except Exception as e:
                    # Don't break your file writer if Mongo is down
                    print(f"[!] Mongo write failed: {e}")
                    mongo_col = None
                    if mongo_client is not None:
                        try:
                            mongo_client.close()
                        except Exception:
                            pass
                        mongo_client = None

            print(f"[+] {event['attack_type']} from {event['src_ip']} -> {event['dst_ip']}:{event['dst_port']}")

if __name__ == "__main__":
    main()