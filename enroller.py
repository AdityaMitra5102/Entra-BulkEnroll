import csv
import getpass
import io
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

from fido2.client import Fido2Client, UserInteraction
from fido2.hid import CtapHidDevice
from fido2.utils import websafe_encode
from fido2.webauthn import PublicKeyCredentialCreationOptions
from fido2.client import DefaultClientDataCollector
from nitrokey.nk3 import NK3
from nitrokey.nkpk import NKPK
from nitrokey.trussed._connection.ctaphid import CtapHidConnection

CLOUD = "https://nkproxy.adityaarghya0.workers.dev/public.php/dav/files/"
INPUT_NAME = "processed.csv"
OUTPUT_NAME = "output.csv"
ORIGIN = "https://login.microsoft.com"  # must be valid for the rp_id in the CSV


def cloud_url(share_id, name):
    return CLOUD + urllib.parse.quote(share_id, safe="") + "/" + name


def cloud_get(share_id, name):
    req = urllib.request.Request(
        cloud_url(share_id, name),
        headers={"User-Agent": "nitrokey-preenrollment"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8-sig")


def cloud_put(share_id, name, text):
    req = urllib.request.Request(
        cloud_url(share_id, name),
        data=text.encode("utf-8"),
        method="PUT",
        headers={"Content-Type": "text/csv;charset=utf-8",
                 "User-Agent": "nitrokey-preenrollment"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.status


def get_display_name(client):
    device = client._backend.ctap2.device
    try:
        name = f"NK3 {str(NK3(CtapHidConnection(device)).uuid())[:5]}"
    except Exception as e:
        print(e)
        try:
            name = f"NKPK {str(NKPK(CtapHidConnection(device)).uuid())[:5]}"
        except Exception:
            name = "FIDO Key"

    return name


def norm(s):
    return re.sub(r"[^a-z0-9]", "", s.lower())


def find_col(headers, *names):
    wanted = {norm(n) for n in names}
    return next((h for h in headers if norm(h) in wanted), None)


class CliInteraction(UserInteraction):
    def prompt_up(self):
        print(">>> Touch your security key now...")

    def request_pin(self, permissions, rp_id):
        return getpass.getpass("Security key PIN: ")

    def request_uv(self, permissions, rp_id):
        print(">>> User verification required on the key.")
        return True


def get_client():
    devices = list(CtapHidDevice.list_devices())
    if not devices:
        raise RuntimeError("No FIDO2 security key found")
    if len(devices) > 1:
        raise RuntimeError(f"{len(devices)} security keys found, plug in only one")
    dev = devices[0]
    if DefaultClientDataCollector is not None:
        return Fido2Client(
            dev,
            client_data_collector=DefaultClientDataCollector(ORIGIN),
            user_interaction=CliInteraction(),
        )
    return Fido2Client(dev, ORIGIN, user_interaction=CliInteraction())


def create_credential(client, upn, display_name, challenge, user_id, rp_id):
    options = PublicKeyCredentialCreationOptions.from_dict({
        "rp": {"id": rp_id, "name": rp_id},
        "user": {"id": user_id, "name": upn, "displayName": display_name},
        "challenge": challenge,
        "pubKeyCredParams": [
            {"type": "public-key", "alg": -7},    # ES256
            {"type": "public-key", "alg": -257},  # RS256
        ],
        "attestation": "direct",
        "authenticatorSelection": {
            "residentKey": "required",
            "requireResidentKey": True,
            "userVerification": "discouraged",
        },
    })
    result = client.make_credential(options)
    resp = getattr(result, "response", result)  # 2.x wraps in .response, 1.x does not
    client_data = bytes(resp.client_data)
    att_obj = resp.attestation_object
    cred_id = att_obj.auth_data.credential_data.credential_id
    return {
        "credential_id": websafe_encode(cred_id),
        "clientDataJson": websafe_encode(client_data),
        "attestationObject": websafe_encode(bytes(att_obj)),
    }

import re

def get_nextcloud_share_id(user_input):
    cleaned_input = user_input.strip()
    
    match = re.search(r"(?:/s/|^)([a-zA-Z0-9]+)/?$", cleaned_input)
    
    if match:
        share_id = match.group(1)
        print(f"Extracted Share ID: {share_id}")
        return share_id
    else:
        print("Invalid share ID or URL format.")
        return None
        
def main():
    share_id = input("Share ID: ")
    share_id = get_nextcloud_share_id(share_id)
    if not share_id:
        sys.exit("Share ID required")
    try:
        text = cloud_get(share_id, INPUT_NAME)
    except urllib.error.HTTPError as e:
        sys.exit(f"Could not fetch {INPUT_NAME}: HTTP {e.code}" + (" (not found)" if e.code == 404 else ""))
    except Exception as e:
        sys.exit(f"Could not reach the cloud: {e}")

    reader = csv.DictReader(io.StringIO(text, newline=""))
    headers = list(reader.fieldnames or [])
    rows = list(reader)

    pcol = find_col(headers, "user principal", "userprincipalname")
    ccol = find_col(headers, "challenge")
    ucol = find_col(headers, "user_id", "user handle", "userhandle")
    rcol = find_col(headers, "rp_id")
    missing = [n for n, c in [("user principal", pcol), ("challenge", ccol),
                              ("user_id", ucol), ("rp_id", rcol)] if not c]
    if missing:
        sys.exit("Missing columns: " + ", ".join(missing))

    out_headers = list(headers)
    for extra in ["display_name", "credential_id", "clientDataJson", "attestationObject", "status"]:
        if not find_col(out_headers, extra):
            out_headers.append(extra)
    dcol = find_col(out_headers, "display_name")
    idcol = find_col(out_headers, "credential_id")
    cdcol = find_col(out_headers, "clientDataJson")
    aocol = find_col(out_headers, "attestationObject")
    scol = find_col(out_headers, "status")
    namecol = find_col(out_headers, "name")

    out_rows = []
    total = len(rows)
    try:
        for i, row in enumerate(rows, 1):
            out = {h: row.get(h, "") for h in out_headers}
            out_rows.append(out)
            upn = (row[pcol] or "").strip()
            challenge = (row[ccol] or "").strip()
            user_id = (row[ucol] or "").strip()
            rp_id = (row[rcol] or "").strip()
            passkey_name = (row[namecol] or upn).strip()

            print(f"\n[{i}/{total}] User principal: {upn}")
            if not (upn and challenge and user_id and rp_id):
                out[scol] = "Skipped: missing principal, challenge, user_id or rp_id"
                print(out[scol])
                continue

            try:
                client = get_client()

                display_name = get_display_name(client)
                out[dcol] = display_name
                print(f"Registering for: {passkey_name}")
                print(f"User principal: {upn}")
                print(f"Display name: {display_name}")
                input("Press Enter to continue...")

                result = create_credential(client, upn, passkey_name, challenge, user_id, rp_id)
                out[idcol] = result["credential_id"]
                out[cdcol] = result["clientDataJson"]
                out[aocol] = result["attestationObject"]
                out[scol] = "Credential created"
                print("OK")
            except Exception as e:
                out[scol] = f"Error: {e}"
                print(out[scol])

            if i < total:
                input("\nChange the security key, then press Enter to continue...")
    except KeyboardInterrupt:
        print("\nInterrupted, writing what has been collected so far.")
    finally:
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=out_headers)
        w.writeheader()
        w.writerows(out_rows)
        data = buf.getvalue()
        try:
            cloud_put(share_id, OUTPUT_NAME, data)
            print(f"\nUploaded {OUTPUT_NAME} to the cloud ({len(out_rows)} rows)")
        except Exception as e:
            with open(OUTPUT_NAME, "w", newline="", encoding="utf-8") as f:
                f.write(data)
            print(f"\nUpload failed ({e}). Saved {OUTPUT_NAME} locally instead ({len(out_rows)} rows)")


if __name__ == "__main__":
    main()
