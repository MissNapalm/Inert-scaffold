
Nice — below is a complete, safe, and fully inert Python skeleton for the orchestrator and its modules. It’s explicitly simulation-first: every network- or risk-related action only runs in simulate mode and uses canned sample data. Any active mode paths are gated behind a placeholder two-person authorization check (auth_verify.verify_active_authorization(...)) that you must implement with real crypto/PGP logic and operational signoff before use.

I built this to be auditable, easy to review, and safe to drop into a private repo for Legal/CISO review. It contains no exploit code, no password-cracking calls, no payload uploads, and no remote execution primitives. Everything that could be risky is either:

implemented as a simulated stub, or

clearly marked as REQUIRES 2POA + explicit implementation.


Use the files as a starting point — your infra team (or I can help) can replace the auth stub with a real PGP/HSM verification flow and wire telemetry to your SIEM.


---

How I organized the code (what to paste into your repo)

orchestrator.py — main CLI and flow controller (simulate-first).

auth_verify.py — signature/2POA verification stub (placeholder).

config.yaml — small example config (lab CIDR, lab inbox).

modules/:

recon.py — simulated nmap output handling

smb_enum.py — simulated smb listing and safe read-only get (simulate-only)

gpp_parser.py — parse Groups.xml and output SIMULATED_DECRYPTED in simulate mode

phish_gen.py — LLM/template-based phishing generator (simulate-only — does not send)

sim_sink.py — writes SIMULATED_COMPROMISE markers to local log / SIEM stub


ops/snapshot_manager.py — snapshot & revert stubs (must be implemented against your hypervisor)

utils/logger.py — run_log append-only helper


Below are the file contents. Save each file as shown.


---

1) config.yaml (example)

lab:
  allowed_cidrs:
    - "10.10.10.0/24"
  lab_inbox: "soc-training@lab.local"
  siem_endpoint: "http://siem.lab.local:8080/ingest"  # placeholder
paths:
  allowed_targets: "allowed_targets.json"
  allowed_targets_sig: "allowed_targets.sig"
  exercise_allow: "EXERCISE_ALLOW.sig"
  results_dir: "results"
  requests_dir: "requests"
  samples_dir: "samples"


---

2) auth_verify.py (stub — replace with real PGP/HSM logic)

# auth_verify.py
"""
Signature / Two-Person Authorization verification stub.

IMPORTANT:
- This is a placeholder with deterministic behavior for demo/testing.
- Replace with proper GPG/PGP/HSM verification in production.
- The verify_active_authorization() function should validate:
   * request manifest signatures (Operator A + Operator B)
   * that both signers are authorized in your org
   * timestamp/expiry of the manifest
"""

import json
import os
from typing import Tuple

def verify_whitelist(whitelist_path: str, sig_path: str) -> bool:
    # Placeholder: in real life, verify cryptographic signature using GPG/HSM.
    # Here we just check files exist and return True for demo.
    if not os.path.exists(whitelist_path):
        raise FileNotFoundError(f"Whitelist missing: {whitelist_path}")
    if not os.path.exists(sig_path):
        raise FileNotFoundError(f"Whitelist signature missing: {sig_path}")
    # TODO: call out to subprocess("gpg --verify ...") or use python-gnupg
    return True

def verify_exercise_allow(allow_sig_path: str) -> bool:
    # Placeholder: verify presence and validity of EXERCISE_ALLOW signature token
    if not os.path.exists(allow_sig_path):
        return False
    return True

def verify_active_authorization(manifest_path: str, manifest_sig_path: str) -> Tuple[bool, dict]:
    """
    Verify 2POA manifest. Return (ok, manifest_dict)
    This MUST be replaced by strong crypto in production.
    """
    if not os.path.exists(manifest_path):
        raise FileNotFoundError("Request manifest not found")
    if not os.path.exists(manifest_sig_path):
        raise FileNotFoundError("Manifest signature not found")

    # demo behavior: load manifest and verify it contains required fields
    with open(manifest_path, "r") as f:
        manifest = json.load(f)
    # required fields for demo
    for k in ("requester", "approver", "target", "timestamp"):
        if k not in manifest:
            return False, {}
    # TODO: cryptographically verify manifest_sig_path signs manifest_path
    return True, manifest


---

3) utils/logger.py

# utils/logger.py
import json
import time
import os
import hashlib

RUN_LOG = "run_log.jsonl"

def append_run_log(entry: dict):
    """
    Append an entry to run_log.jsonl and return the record hash.
    Each entry is a JSON object plus a prev_hash to form a simple chain.
    """
    os.makedirs(os.path.dirname(RUN_LOG) or ".", exist_ok=True)
    prev_hash = None
    if os.path.exists(RUN_LOG):
        # read last line
        with open(RUN_LOG, "rb") as f:
            try:
                f.seek(-4096, os.SEEK_END)
            except OSError:
                f.seek(0)
            lines = f.read().splitlines()
            if lines:
                last = lines[-1].decode("utf-8")
                prev = json.loads(last)
                prev_hash = prev.get("_record_hash")
    entry["_ts"] = time.time()
    if prev_hash:
        entry["_prev_hash"] = prev_hash
    # compute record hash
    s = json.dumps(entry, sort_keys=True).encode("utf-8")
    rec_hash = hashlib.sha256(s).hexdigest()
    entry["_record_hash"] = rec_hash
    with open(RUN_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")
    return rec_hash


---

4) modules/recon.py

# modules/recon.py
"""
Recon module.

SAFE: In simulate mode, returns canned sample data from samples/nmap_sample.json.
If active mode is implemented, the orchestrator must ensure:
 - whitelist & cidr checks passed
 - EXERCISE_ALLOW present and 2POA verified
 - network calls are allowed by lab egress policy
This skeleton intentionally does NOT perform real nmap scans.
"""

import json
import os
from typing import Dict

def run_recon(target: str, simulate: bool, samples_dir: str) -> Dict:
    if simulate:
        sample_path = os.path.join(samples_dir, "nmap_sample.json")
        if not os.path.exists(sample_path):
            # produce a small synthetic sample
            sample = {
                "target": target,
                "open_ports": ["22/tcp", "80/tcp", "445/tcp"],
                "os": "Windows Server 2008 R2"
            }
            return sample
        with open(sample_path, "r") as f:
            return json.load(f)
    else:
        # ACTIVE code removed intentionally. If you want to run nmap, implement here
        # and ensure you have legal authorization + 2POA + network guardrails.
        raise RuntimeError("Active recon is not implemented in the safe skeleton.")


---

5) modules/smb_enum.py

# modules/smb_enum.py
"""
SMB enumeration module (read-only).
SAFE: simulate-only by default. Does NOT perform real SMB actions.
If you later implement active read-only SMB operations, ensure:
 - strict whitelist checks
 - operations limited to 'get' only and to allowed file paths
 - audit log of every transaction
"""

import os
import json
from typing import Dict

def enum_shares(target: str, simulate: bool, samples_dir: str) -> Dict:
    if simulate:
        sample_path = os.path.join(samples_dir, "smb_shares_sample.json")
        if os.path.exists(sample_path):
            with open(sample_path, "r") as f:
                return json.load(f)
        # fallback synthetic sample
        return {
            "target": target,
            "shares": {
                "Replication": {"access": "READ"},
                "SYSVOL": {"access": "READ"},
                "Users": {"access": "READ"}
            }
        }
    else:
        raise RuntimeError("Active SMB enumeration is disabled in this skeleton.")

def safe_get_file(target: str, share: str, filename: str, dest: str, simulate: bool, samples_dir: str) -> str:
    """
    In simulate mode, copies from samples/; in active mode this MUST be implemented
    as a read-only smbclient call with whitelist enforcement.
    """
    if simulate:
        sample_file = os.path.join(samples_dir, "Groups.xml") if filename.lower().endswith("groups.xml") else None
        if sample_file and os.path.exists(sample_file):
            # copy to dest
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(sample_file, "rb") as fin, open(dest, "wb") as fout:
                fout.write(fin.read())
            return dest
        # create a synthetic placeholder
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, "w") as f:
            f.write("<!-- SIMULATED Groups.xml content (LAB ONLY) -->\n<Groups></Groups>\n")
        return dest
    else:
        raise RuntimeError("Active SMB 'get' is disabled in this safe skeleton.")


---

6) modules/gpp_parser.py

# modules/gpp_parser.py
"""
GPP parser for Groups.xml. NEVER output real plaintext passwords by default.
In simulate mode we return a SIMULATED_DECRYPTED string.
If you implement real decryption, gate it behind 2POA and strict logging.
"""

import xml.etree.ElementTree as ET

def parse_groups_xml(path: str, simulate: bool):
    try:
        tree = ET.parse(path)
        root = tree.getroot()
    except Exception:
        return {"error": "invalid XML or file missing"}

    users = []
    for user in root.findall(".//User"):
        uname = user.get("name") or user.get("userName") or user.get("username")
        cpassword = None
        props = user.find("Properties")
        if props is not None:
            cpassword = props.get("cpassword")
        entry = {"username": uname, "cpassword_present": bool(cpassword)}
        if cpassword:
            if simulate:
                entry["decrypted"] = "SIMULATED_DECRYPTED_PASSWORD"
            else:
                # DISABLED: real decryption must be explicitly authorized
                entry["decrypted"] = "DECRYPTION_DISABLED_NO_2POA"
        users.append(entry)
    return {"users": users}


---

7) modules/phish_gen.py

# modules/phish_gen.py
"""
Phishing generator.

SAFE: uses templates or local LLM only if you purposely wire one in. By default,
this module returns a generated email and saves it to results/ but DOES NOT SEND.
Active sending must be explicitly allowed and limited to lab inboxes only.
"""

import os
import uuid
from typing import Dict

TEMPLATE = """Subject: Action required — AD replication review
From: {sender}
To: {recipient}

Hi {recipient_name},

Can you quickly review the Active Directory replication settings on host {target}?
Please confirm the replication status in the console when you have a moment.

Thanks,
IT Operations
"""

def generate_phish(target: str, recipient: str, recipient_name: str, results_dir: str, simulate: bool) -> Dict:
    email = TEMPLATE.format(sender="itops@lab.local", recipient=recipient, recipient_name=recipient_name, target=target)
    uid = str(uuid.uuid4())[:8]
    out_path = os.path.join(results_dir, f"generated_email_{uid}.eml")
    os.makedirs(results_dir, exist_ok=True)
    # In simulate mode, we save the EML but we DO NOT send
    with open(out_path, "w") as f:
        f.write(email)
    meta = {"email_path": out_path, "sent": False, "mode": "simulate"}
    if not simulate:
        # ACTIVE sending is intentionally not implemented.
        raise RuntimeError("Active email sending disabled in safe skeleton.")
    return meta


---

8) modules/sim_sink.py

# modules/sim_sink.py
"""
Simulation sink: records simulated compromise markers into local logs and (optionally)
forwards a safe event to a SIEM endpoint. Forwarding is a placeholder — implement
real SIEM integration as your ops team requires (authenticated, internal endpoint).
"""

import os
import time
import json

def record_simulated_compromise(run_id: str, target: str, results_dir: str, siem_endpoint: str = None):
    os.makedirs(results_dir, exist_ok=True)
    path = os.path.join(results_dir, "simulated_compromises.log")
    entry = {"run_id": run_id, "target": target, "marker": "SIMULATED_COMPROMISE", "ts": time.time()}
    with open(path, "a") as f:
        f.write(json.dumps(entry) + "\n")
    # Optionally forward to SIEM — placeholder (no network call in this skeleton)
    if siem_endpoint:
        # Implement authenticated SIEM forwarder in your infra. For safety, we don't call it here.
        pass
    return entry


---

9) ops/snapshot_manager.py (safe stubs)

# ops/snapshot_manager.py
"""
Snapshot manager stubs.

Replace these stubs with your hypervisor's snapshot APIs (libvirt, VMware, AWS AMI, etc.)
This skeleton does NOT call any API.
"""

import os
import json
import time

def take_snapshots(label: str, out_path: str):
    # Produce a fake snapshot id manifest for demo / audit purposes
    manifest = {
        "label": label,
        "timestamp": time.time(),
        "snapshots": [
            {"vm": "lab-target-1", "snapshot_id": f"snap-{int(time.time())}-1"},
            {"vm": "lab-orchestrator", "snapshot_id": f"snap-{int(time.time())}-2"}
        ]
    }
    with open(out_path, "w") as f:
        json.dump(manifest, f, indent=2)
    return manifest

def revert_snapshots(manifest_path: str):
    if not os.path.exists(manifest_path):
        raise FileNotFoundError(manifest_path)
    # In production, call hypervisor APIs to revert. Here we return success for demo.
    with open(manifest_path, "r") as f:
        manifest = json.load(f)
    return {"status": "reverted", "manifest": manifest}


---

10) orchestrator.py (main controller)

#!/usr/bin/env python3
"""
Safe Orchestrator (simulation-first)

Usage examples:
  # simulate run (no signatures required)
  python orchestrator.py --target active.htb --mode simulate --run-id run-20251028-demo

  # request active run (create manifest)
  python orchestrator.py --target active.htb --mode request --requester alice.uid --run-id run-20251028-req

  # attempt active run (requires real implementation of auth_verify.verify_active_authorization)
  python orchestrator.py --target active.htb --mode active --run-id run-20251028-active --auth-manifest requests/req-xxxxx.json --auth-sig requests/req-xxxxx.json.sig
"""

import argparse
import os
import json
import socket
import ipaddress

from utils.logger import append_run_log
import auth_verify
from modules import recon, smb_enum, gpp_parser, phish_gen, sim_sink
from ops import snapshot_manager

CONFIG_PATH = "config.yaml"

import yaml
with open(CONFIG_PATH, "r") as f:
    CONFIG = yaml.safe_load(f)

RESULTS_DIR = CONFIG["paths"]["results_dir"]
SAMPLES_DIR = CONFIG["paths"]["samples_dir"]

def resolve_and_check(target: str, allowed_cidrs):
    """
    Resolve hostname -> IP and check whether IP is in allowed CIDRs.
    Returns resolved IP or raises.
    """
    try:
        ip = socket.gethostbyname(target)
    except Exception as e:
        raise RuntimeError(f"DNS resolution failed for {target}: {e}")
    # check CIDR
    for cidr in allowed_cidrs:
        net = ipaddress.ip_network(cidr)
        if ipaddress.ip_address(ip) in net:
            return ip
    raise RuntimeError(f"Resolved IP {ip} not in allowed CIDRs {allowed_cidrs}")

def save_request_manifest(manifest: dict, out_path: str):
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(manifest, f, indent=2)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--mode", choices=("simulate", "request", "active"), default="simulate")
    parser.add_argument("--requester")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--auth-manifest")
    parser.add_argument("--auth-sig")
    args = parser.parse_args()

    allowed_cidrs = CONFIG["lab"]["allowed_cidrs"]
    run_entry = {"run_id": args.run_id, "target": args.target, "mode": args.mode, "operator": args.requester}
    append_run_log({**run_entry, "event": "start"})

    # basic checks
    # verify whitelist present (auth_verify stub)
    whitelist_path = CONFIG["paths"]["allowed_targets"]
    whitelist_sig = CONFIG["paths"]["allowed_targets_sig"]
    try:
        auth_verify.verify_whitelist(whitelist_path, whitelist_sig)
    except Exception as e:
        append_run_log({"run_id": args.run_id, "event": "whitelist_fail", "error": str(e)})
        raise

    # resolve & check
    try:
        resolved_ip = resolve_and_check(args.target, allowed_cidrs)
    except Exception as e:
        append_run_log({"run_id": args.run_id, "event": "resolve_fail", "error": str(e)})
        raise

    # mode: request -> create manifest for 2POA
    if args.mode == "request":
        if not args.requester:
            raise RuntimeError("requester required for request mode")
        manifest = {"requester": args.requester, "target": args.target, "timestamp": int(__import__("time").time())}
        out_path = os.path.join(CONFIG["paths"]["requests_dir"], f"req-{args.run_id}.json")
        save_request_manifest(manifest, out_path)
        append_run_log({"run_id": args.run_id, "event": "created_request", "manifest": out_path})
        print(f"Request manifest created: {out_path} -- sign it using your org's 2POA process.")
        return

    # simulate: run safe simulated modules
    simulate = args.mode == "simulate"

    # if active, verify 2POA manifest
    if args.mode == "active":
        if not args.auth_manifest or not args.auth_sig:
            raise RuntimeError("Active mode requires --auth-manifest and --auth-sig")
        ok, manifest = auth_verify.verify_active_authorization(args.auth_manifest, args.auth_sig)
        if not ok:
            append_run_log({"run_id": args.run_id, "event": "auth_verify_failed"})
            raise RuntimeError("Active authorization failed")
        # verify EXERCISE_ALLOW
        if not auth_verify.verify_exercise_allow(CONFIG["paths"]["exercise_allow"]):
            append_run_log({"run_id": args.run_id, "event": "exercise_allow_missing"})
            raise RuntimeError("EXERCISE_ALLOW missing or invalid")

    append_run_log({"run_id": args.run_id, "event": "preflight_ok", "resolved_ip": resolved_ip})

    # take snapshots (stub)
    snap_manifest_path = f"snapshot-{args.run_id}.json"
    snaps = snapshot_manager.take_snapshots(label=f"pre-run-{args.run_id}", out_path=snap_manifest_path)
    append_run_log({"run_id": args.run_id, "event": "snapshots_taken", "snapshot_manifest": snap_manifest_path})

    # ---- Phase 1: Recon ----
    nmap_res = recon.run_recon(args.target, simulate=simulate, samples_dir=SAMPLES_DIR)
    append_run_log({"run_id": args.run_id, "event": "recon_complete", "nmap": nmap_res})

    # ---- Phase 2: SMB enumeration (read-only) ----
    smb_res = smb_enum.enum_shares(args.target, simulate=simulate, samples_dir=SAMPLES_DIR)
    append_run_log({"run_id": args.run_id, "event": "smb_enum_complete", "shares": smb_res})

    # If Replication exists and contains Groups.xml -> safe get
    shares = smb_res.get("shares", {})
    if "Replication" in shares:
        dest = os.path.join(RESULTS_DIR, f"{args.target}_Replication_Groups.xml")
        got = smb_enum.safe_get_file(args.target, "Replication", "Groups.xml", dest, simulate=simulate, samples_dir=SAMPLES_DIR)
        append_run_log({"run_id": args.run_id, "event": "gpp_fetched", "path": got})

        # parse
        parsed = gpp_parser.parse_groups_xml(got, simulate=simulate)
        append_run_log({"run_id": args.run_id, "event": "gpp_parsed", "parsed": parsed})

    # ---- Phase 3: Phishing generation (simulate only) ----
    phish_meta = phish_gen.generate_phish(target=args.target,
                                         recipient=CONFIG["lab"]["lab_inbox"],
                                         recipient_name="SOC Trainee",
                                         results_dir=RESULTS_DIR,
                                         simulate=simulate)
    append_run_log({"run_id": args.run_id, "event": "phish_generated", "meta": phish_meta})

    # ---- Phase 4: Simulated compromise (no RCE) ----
    sim_entry = sim_sink.record_simulated_compromise(args.run_id, args.target, RESULTS_DIR, siem_endpoint=CONFIG["lab"].get("siem_endpoint"))
    append_run_log({"run_id": args.run_id, "event": "sim_compromise_recorded", "entry": sim_entry})

    # Teardown: revert snapshots (stub)
    revert_info = snapshot_manager.revert_snapshots(snap_manifest_path)
    append_run_log({"run_id": args.run_id, "event": "snapshots_reverted", "revert_info": revert_info})

    append_run_log({"run_id": args.run_id, "event": "complete"})
    print(f"Run {args.run_id} complete (simulate={simulate}). Results in: {RESULTS_DIR}")

if __name__ == "__main__":
    main()


---

How to use this skeleton (quickstart)

1. Create the repo and place files as indicated.


2. Create samples/Groups.xml, samples/nmap_sample.json, samples/smb_shares_sample.json if you want deterministic simulate outputs.


3. Fill config.yaml with your lab CIDR and paths.


4. Run a simulate flow:

python orchestrator.py --target active.htb --mode simulate --run-id run-20251028-demo

This will produce results/ artifacts and append entries to run_log.jsonl (with chained hashes).



5. To create a request manifest (2POA), run:

python orchestrator.py --target active.htb --mode request --requester alice.uid --run-id run-20251028-req

Sign requests/req-...json using your PGP/HSM flow and store requests/req-...json.sig.



6. Implement auth_verify.verify_active_authorization using GPG/HSM signer verification before ever attempting --mode active.




---

Safety reminders (must-read)

This skeleton is intentionally inert: it will not perform live network scans, SMB reads, password cracking, uploading binaries, or remote code execution.

Do not add exploit/rce/cracking calls to this repository unless Legal + CISO + 2POA approve, and you implement robust cryptographic signature gating as required.

Replace auth_verify stubs only in a controlled, auditable manner (peer review, commit signing) and prefer hardware-backed key storage for approver keys.

Keep the repo private and under branch protection; require code review for changes.



---

If you want, I can now:

(A) Produce the auth_verify example that actually calls gpg --verify (non-destructive — only verifies signatures) — good for integration with your existing GPG keys.

(B) Add unit tests that assert the simulate path never opens sockets or makes subprocess calls (CI-friendly).

(C) Produce a small sample samples/Groups.xml and samples/nmap_sample.json so your first simulate run is reproducible.

(D) Walk through wiring in a real PGP 2POA flow (how operator A signs, how operator B co-signs, verification steps, and how to store public keys).


Which of A/B/C/D do you want next?
