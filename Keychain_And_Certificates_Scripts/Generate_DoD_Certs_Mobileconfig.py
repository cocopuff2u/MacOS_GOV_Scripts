#!/usr/bin/python3

####################################################################################################
#
# # Generate DoD Certificates Mobileconfig
#
# Purpose: This script generates a macOS configuration profile (.mobileconfig) containing the latest
# DoD PKI certificates. This can be uploaded to an MDM solution or installed manually on macOS devices.
#
# https://github.com/cocopuff2u
#
####################################################################################################
#
#   History
#
#  1.0 6/04/25 - Original
#  1.1 9/26/25 - Adjusted for new DoD Url
#  2.0 10/15/25 - Logging improvements, robust PKCS#7 and PEM handling, expiry filtering, name
# disambiguation, add support for other (WCF, JITC, ECA) certificate sets.
#
####################################################################################################

SCRIPT_VERSION = "2.0"

# Global toggle: default behavior to skip expired certificates (can be overridden by --skip-expired)
SKIP_EXPIRED = False

# Top-level toggle: comment items out to disable
ENABLED_SOURCES = [
    "dod",
    "wcf",
    "jitc",
    "eca",
]


####################################################################################################
#   Usage
#     python3 Untitled-1.py [options]
#
#   Options
#     -r, --removal-allowed       Allow users to remove the installed profile.
#         --organization ORG      Organization name to stamp into the profile.
#     -o, --output PATH           Output .mobileconfig path (ignored when multiple sources).
#     -e, --export-certs          Export individual certs to ./certs/<profile> as PEM files.
#     -x, --skip-expired          Skip certificates that are expired (default controlled by SKIP_EXPIRED).
#         --source SRC            Which cert set(s) to include:
#                                 'dod' | 'wcf' | 'jitc' | 'eca' | 'both' (dod+wcf) | 'all' | 'config' (default).
#         --timeout SECONDS       Network timeout when downloading the ZIP (default: 30).
#         --retries N             Retry count for downloading the ZIP (default: 3).
#
#   Examples
#     python3 Untitled-1.py --source dod -x -e
#     python3 Untitled-1.py --source all --organization "My Org" --timeout 45 --retries 5
#
####################################################################################################

# Unified source definitions (clean and consistent)
SOURCES = {
    "dod": {
        "zip_url": "https://dl.dod.cyber.mil/wp-content/uploads/pki-pke/zip/unclass-certificates_pkcs7_DoD.zip",
        "profile_title": "DoD_PKI_Chain",
        "display_prefix": "DoD_Certificates",
        "description_prefix": "Latest DoD Certificates from https://cyber.mil",
    },
    "wcf": {
        "zip_url": "https://dl.dod.cyber.mil/wp-content/uploads/pki-pke/zip/unclass-certificates_pkcs7_WCF.zip",
        "profile_title": "WCF_BI_PKI_Chain",
        "display_prefix": "WCF_Certificates",
        "description_prefix": "Latest WCF B&I Certificates from https://cyber.mil",
    },
    "jitc": {
        "zip_url": "https://dl.dod.cyber.mil/wp-content/uploads/pki-pke/zip/unclass-certificates_pkcs7_JITC.zip",
        "profile_title": "JITC_PKI_Chain",
        "display_prefix": "JITC_Certificates",
        "description_prefix": "Latest JITC Certificates from https://cyber.mil",
    },
    "eca": {
        "zip_url": "https://dl.dod.cyber.mil/wp-content/uploads/pki-pke/zip/unclass-certificates_pkcs7_ECA.zip",
        "profile_title": "ECA_PKI_Chain",
        "display_prefix": "ECA_Certificates",
        "description_prefix": "Latest ECA Certificates from https://cyber.mil",
    },
}

import base64
import io
import argparse
import os
import os.path
import re
import ssl
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
import hashlib
import shutil
import time
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from html.parser import HTMLParser
from pathlib import Path
from plistlib import dump
from urllib.parse import urlparse
from uuid import uuid4


class URLHtmlParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag != "a":
            return
        for attr in attrs:
            if "href" in attr[0]:
                self.links.append(attr[1])
                break


class ConfigurationProfile:
    """Class to create and manipulate Configuration Profiles."""

    def __init__(
        self,
        identifier,
        uuid=False,
        removal_allowed=False,
        organization="",
        displayname="",
        export=False,
    ):
        self.data = {}
        self.data["PayloadVersion"] = 1
        self.data["PayloadOrganization"] = organization
        if uuid:
            self.data["PayloadUUID"] = uuid
        else:
            self.data["PayloadUUID"] = makeNewUUID()
        if removal_allowed:
            self.data["PayloadRemovalDisallowed"] = False
        else:
            self.data["PayloadRemovalDisallowed"] = True
        self.data["PayloadType"] = "Configuration"
        self.data["PayloadScope"] = "System"
        self.data["PayloadDescription"] = displayname
        self.data["PayloadDisplayName"] = displayname
        self.data["PayloadIdentifier"] = makeNewUUID()

        # An empty list for 'sub payloads' that we'll fill later
        self.data["PayloadContent"] = []

        self.export = export
        self.processed_certs = set()  # Track processed certificates (CNs)
        # New: track unique certs by fingerprint and handle name collisions
        self.processed_hashes = set()
        self.name_counts = defaultdict(int)
        self.used_display_names = set()

    def _addCertificatePayload(self, payload_content, certname, certtype):
        """Add a Certificate payload to the profile. Takes a dict which will be the
        PayloadContent dict within the payload.
        """
        payload_dict = {}
        payload_dict["PayloadVersion"] = 1
        payload_dict["PayloadUUID"] = makeNewUUID()
        payload_dict["PayloadEnabled"] = True

        if certtype == "root":
            payload_dict["PayloadType"] = "com.apple.security.root"
            payload_dict["PayloadIdentifier"] = (
                "com.apple.security.root." + payload_dict["PayloadUUID"]
            )
        else:
            payload_dict["PayloadType"] = "com.apple.security.pkcs1"
            payload_dict["PayloadIdentifier"] = (
                "com.apple.security.pkcs1." + payload_dict["PayloadUUID"]
            )

        payload_dict["PayloadDisplayName"] = certname
        payload_dict["AllowAllAppsAccess"] = True
        # Use sanitized filename to avoid plist issues across all sources (e.g., WCF)
        payload_dict["PayloadCertificateFileName"] = sanitize_filename(certname) + ".cer"
        payload_dict["KeyIsExtractable"] = True
        payload_dict["PayloadDescription"] = "Adds a PKCS#1-formatted certificate"

        # Add our actual content
        payload_dict["PayloadContent"] = payload_content

        # Add to the profile's PayloadContent array
        self.data["PayloadContent"].append(payload_dict)

    def addPayloadFromPEM(self, pemfile):
        """Add Certificates to the profile's payloads."""
        payload_content = ""
        regex_pattern = "(-+BEGIN CERTIFICATE-+)(.*?)(-+END CERTIFICATE-+)"
        regex = re.compile(regex_pattern, flags=re.MULTILINE | re.DOTALL)
        cert = regex.search(pemfile)

        payload_content = cert.group(2)
        payload_content_ascii = payload_content.encode("ascii")
        payload_content_bytes = base64.b64decode(payload_content_ascii)

        # New: compute fingerprint to detect true duplicates
        fingerprint = hashlib.sha256(payload_content_bytes).hexdigest()
        if fingerprint in self.processed_hashes:
            # True duplicate content; skip
            return

        # Always derive names from the certificate itself for correctness
        subj_cn, iss_cn = parse_subject_issuer_from_pem(cert.group(0))
        base_name = (subj_cn or "Unnamed Certificate").strip()
        issuer = (iss_cn or "").strip()

        # Determine type
        certtype = "root" if issuer and issuer == base_name else "intermediate"

        # Disambiguate display name when multiple certs share same CN
        serial_tail = get_cert_serial_tail(pemfile)  # e.g., last 8 hex of serial or ""
        display_name = base_name
        if base_name in self.used_display_names:
            if serial_tail:
                display_name = f"{base_name} [{serial_tail}]"
            else:
                self.name_counts[base_name] += 1
                display_name = f"{base_name} ({self.name_counts[base_name]})"
        self.used_display_names.add(display_name)

        print(f"Adding {display_name} to profile...")
        self._addCertificatePayload(bytes(payload_content_bytes), display_name, certtype)

        # Track processed sets
        self.processed_hashes.add(fingerprint)
        self.processed_certs.add(base_name)  # kept for compatibility

        # write PEM to file
        if self.export:
            print(f"Writing {display_name}.pem to certs folder...")
            self._writePEMtoFile(pemfile, display_name)

    def _writePEMtoFile(self, pemfile, name):
        # Export under a per-profile directory to avoid cross-zip mixing
        profile_dir = sanitize_filename(self.data.get("PayloadDisplayName", "profile"))
        base_dir = Path("./certs") / profile_dir
        base_dir.mkdir(parents=True, exist_ok=True)
        safe_name = sanitize_filename(name)
        output_path = base_dir / f"{safe_name}.pem"
        with open(output_path, "w") as cert_file:
            cert_file.write(pemfile)

    def finalizeAndSave(self, output_path):
        """Perform last modifications and save to an output plist."""
        print(f"Writing .mobileconfig file to: {output_path}")
        with open(output_path, "wb+") as plist_file:
            dump(self.data, plist_file)


def makeNewUUID():
    return str(uuid4())


def errorAndExit(errmsg):
    print(errmsg, file=sys.stderr)
    sys.exit(-1)


def extract_dod_cert_url(content):
    """Takes the html content and parses the href tags to collect links.  Looks for the DoD.zip in the links and returns that URL"""
    parser = URLHtmlParser()
    parser.feed(content)
    for url in parser.links:
        if "DoD.zip" in url:
            return url
    return


def extract_dod_cert_zip_file(zip_url, tempdir, timeout=30, retries=3):
    """Download the ZIP with retries/timeouts and extract to tempdir. Returns the basename of the downloaded ZIP URL."""
    req = urllib.request.Request(
        zip_url,
        headers={"User-Agent": f"DoD-PKI-Downloader/{SCRIPT_VERSION} (+https://cyber.mil)"}
    )
    last_err = None
    for attempt in range(1, int(retries) + 1):
        try:
            with urllib.request.urlopen(req, context=ssl._create_unverified_context(), timeout=timeout) as r:
                data = r.read()
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                zf.extractall(tempdir)
            return os.path.basename(urlparse(zip_url).path)
        except Exception as e:
            last_err = e
            if attempt < int(retries):
                backoff = min(2 ** attempt, 10)
                print(f"Download failed (attempt {attempt}/{retries}): {e}. Retrying in {backoff}s...")
                time.sleep(backoff)
            else:
                print(f"Error: Failed to download or extract ZIP after {retries} attempts: {e}")
                raise


def extract_bundle_version(text):
    """Try to extract a version like vX_Y or vX.Y from filenames/dirnames."""
    patterns = [
        r'Certificates_PKCS7_v(\d+[_\.]\d+)_',
        r'certificates_pkcs7_v(\d+[_\.]\d+)_',
        r'WCF.*?_v(\d+[_\.]\d+)',
        r'certificates_pkcs7_WCF_v(\d+[_\.]\d+)',
        r'JITC.*?_v(\d+[_\.]\d+)',
        r'certificates_pkcs7_JITC_v(\d+[_\.]\d+)',
        r'ECA.*?_v(\d+[_\.]\d+)',
        r'certificates_pkcs7_ECA_v(\d+[_\.]\d+)',
        r'\bv(\d+[_\.]\d+)\b',
    ]
    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            return m.group(1).replace('_', '.')
    return "unknown"

_EXPIRY_WARNED = False  # one-time warning flag

def _parse_not_after(date_str):
    """
    Parse an OpenSSL notAfter string into an aware UTC datetime.
    Supports 'GMT'/'UTC' or no timezone.
    """
    date_str = date_str.strip()
    fmts = [
        "%b %d %H:%M:%S %Y %Z",  # e.g., Jun  7 12:00:00 2027 GMT
        "%b %d %H:%M:%S %Y",     # without timezone
    ]
    for fmt in fmts:
        try:
            dt = datetime.strptime(date_str, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    raise ValueError(f"Unrecognized notAfter format: {date_str}")

def cert_is_expired(pem_text):
    """
    Returns True only when we can confidently determine the certificate is expired.
    Uses a temporary file with openssl to avoid stdin parsing issues.
    Flow:
      1) Read notAfter via `openssl x509 -noout -enddate -in <tmp>`, compare to now (UTC).
      2) If step 1 fails, fallback to `openssl x509 -noout -checkend 0 -in <tmp>`.
      3) If still uncertain, return False (do not skip).
    Enable DOD_CERTS_DEBUG_EXPIRY=1 for verbose logging.
    """
    global _EXPIRY_WARNED
    debug = os.environ.get("DOD_CERTS_DEBUG_EXPIRY") == "1"

    m = re.search(r"(-+BEGIN CERTIFICATE-+.*?-+END CERTIFICATE-+)", pem_text, re.DOTALL)
    if not m:
        if debug:
            print("expiry: no PEM block found -> not expired")
        return False
    pem_block = m.group(1).encode("ascii", errors="ignore")

    tmp_path = None
    try:
        # Write PEM block to a temp file for robust openssl parsing
        tf = tempfile.NamedTemporaryFile(mode="wb", suffix=".pem", delete=False)
        tmp_path = tf.name
        tf.write(pem_block)
        tf.flush()
        tf.close()

        # Primary: parse notAfter from file
        res = subprocess.run(
            ["openssl", "x509", "-noout", "-enddate", "-in", tmp_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        if res.returncode == 0:
            line = res.stdout.decode("utf-8", "ignore").strip()
            # Expected: notAfter=Jun  7 12:00:00 2027 GMT
            _, _, date_str = line.partition("=")
            try:
                not_after = _parse_not_after(date_str)
                now = datetime.now(timezone.utc)
                expired = not_after <= now
                if debug:
                    print(f"expiry: notAfter={not_after.isoformat()} now={now.isoformat()} -> expired={expired}")
                return expired
            except Exception as e:
                if debug:
                    print(f"expiry: _parse_not_after failed: {e}")
                # fall through to checkend

        if debug and res.returncode != 0:
            print(f"expiry: enddate rc={res.returncode}, stderr={res.stderr.decode('utf-8','ignore').strip()}")

        # Fallback: checkend from file
        res2 = subprocess.run(
            ["openssl", "x509", "-noout", "-checkend", "0", "-in", tmp_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        if debug:
            print(f"expiry: checkend rc={res2.returncode}")
        if res2.returncode == 0:
            return False
        elif res2.returncode == 1:
            return True
        else:
            if not _EXPIRY_WARNED:
                print("Warning: openssl returned an unexpected code while checking expiry; treating as not expired.")
                _EXPIRY_WARNED = True
            return False

    except FileNotFoundError:
        if not _EXPIRY_WARNED:
            print("Warning: openssl not found; cannot check expiry. Proceeding without expiry filtering.")
            _EXPIRY_WARNED = True
        return False
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

def find_p7b_file(tempdir, title_hint="DoD_PKI_Chain"):
    """Attempts to return paths to all pkcs7 bundle files, prioritizing Root CA files"""
    root_p7b_files = []
    other_p7b_files = []
    bundle_version = "unknown"
    
    # Try to find version from directory names using a few patterns
    for dirpath, subdir, files in os.walk(tempdir):
        dirname = os.path.basename(dirpath)
        maybe_ver = extract_bundle_version(dirname)
        if maybe_ver != "unknown":
            bundle_version = maybe_ver
            break
            
    for dirpath, subdir, files in os.walk(tempdir):
        for file in files:
            if file.endswith(".p7b"):
                full_path = os.path.join(dirpath, file)
                if "Root_CA" in file:
                    print(f"Found Root CA bundle: {file}")
                    root_p7b_files.append(full_path)
                else:
                    print(f"Found certificate bundle: {file}")
                    other_p7b_files.append(full_path)
    
    if not root_p7b_files and not other_p7b_files:
        print("Info: No .p7b files found; will look for PEM files instead.")
        return [], title_hint, bundle_version
        
    print(f"Found {len(root_p7b_files)} Root CA bundles and {len(other_p7b_files)} other certificate bundles")
    return root_p7b_files + other_p7b_files, title_hint, bundle_version

# New: discover PEM-like files in extracted zip
def find_pem_files(tempdir):
    pem_like_exts = {".pem", ".crt", ".cer"}
    pem_files = []
    for dirpath, subdir, files in os.walk(tempdir):
        for f in files:
            if os.path.splitext(f)[1].lower() in pem_like_exts:
                pem_files.append(os.path.join(dirpath, f))
    return pem_files

# New: split a text into individual PEM certificate blocks
def extract_cert_blocks(text):
    return re.findall(r"-+BEGIN CERTIFICATE-+.*?-+END CERTIFICATE-+", text, re.DOTALL)

# New: get subject/issuer CNs from a PEM block using openssl
def parse_subject_issuer_from_pem(pem_text):
    """
    Returns (subject_cn, issuer_cn) strings ('' if unavailable).
    Uses a temporary file for robust openssl parsing.
    """
    m = re.search(r"(-+BEGIN CERTIFICATE-+.*?-+END CERTIFICATE-+)", pem_text, re.DOTALL)
    if not m:
        return "", ""
    pem_block = m.group(1).encode("ascii", errors="ignore")
    tmp_path = None
    try:
        tf = tempfile.NamedTemporaryFile(mode="wb", suffix=".pem", delete=False)
        tmp_path = tf.name
        tf.write(pem_block)
        tf.flush()
        tf.close()

        res = subprocess.run(
            ["openssl", "x509", "-noout", "-subject", "-issuer", "-in", tmp_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        if res.returncode != 0:
            return "", ""
        out = res.stdout.decode("utf-8", "ignore")
        subj_line = ""
        iss_line = ""
        for line in out.splitlines():
            if line.lower().startswith("subject="):
                subj_line = line
            elif line.lower().startswith("issuer="):
                iss_line = line

        cn_pat = re.compile(r"CN\s*=\s*([^/\n,]+)")
        subj_cn = ""
        iss_cn = ""

        # Support both '/.../CN=foo/...' and '... CN= foo, ...'
        m1 = cn_pat.search(subj_line) or re.search(r"/CN=([^/\n]+)", subj_line)
        if m1:
            subj_cn = m1.group(1).strip()

        m2 = cn_pat.search(iss_line) or re.search(r"/CN=([^/\n]+)", iss_line)
        if m2:
            iss_cn = m2.group(1).strip()

        return subj_cn, iss_cn
    except FileNotFoundError:
        return "", ""
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

# New: get short serial suffix for name disambiguation
def get_cert_serial_tail(pem_text):
    """
    Return the last 8 hex chars of the certificate serial (for disambiguation), or '' on failure.
    """
    m = re.search(r"(-+BEGIN CERTIFICATE-+.*?-+END CERTIFICATE-+)", pem_text, re.DOTALL)
    if not m:
        return ""
    pem_block = m.group(1).encode("ascii", errors="ignore")
    try:
        res = subprocess.run(
            ["openssl", "x509", "-noout", "-serial", "-inform", "pem", "-in", "-"],
            input=pem_block, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False
        )
        if res.returncode != 0:
            return ""
        # Output like: serial=01ABCD...
        out = res.stdout.decode("utf-8", "ignore").strip()
        parts = out.split("=", 1)
        hex_serial = parts[1].strip() if len(parts) == 2 else ""
        hex_serial = re.sub(r"[^0-9A-Fa-f]", "", hex_serial)
        return hex_serial[-8:].upper() if hex_serial else ""
    except FileNotFoundError:
        return ""

# New: sanitize filenames from display names
def sanitize_filename(name):
    # Replace slashes and other unsafe chars
    name = re.sub(r"[\\/:\*\?\"<>\|\t\n\r]", "_", name)
    name = re.sub(r"\s+", " ", name).strip()
    return name


# New: helper to get the raw notAfter string for logging
def get_cert_not_after(pem_text):
    """
    Returns the 'Not Valid After' date string. Tries -enddate first, then falls back to
    parsing 'Not After'/'Not Valid After' from `openssl x509 -text`.
    Uses a temporary file to avoid stdin parsing issues.
    """
    m = re.search(r"(-+BEGIN CERTIFICATE-+.*?-+END CERTIFICATE-+)", pem_text, re.DOTALL)
    if not m:
        return ""
    pem_block = m.group(1).encode("ascii", errors="ignore")

    tmp_path = None
    try:
        # Write PEM block to a temp file for robust openssl parsing
        tf = tempfile.NamedTemporaryFile(mode="wb", suffix=".pem", delete=False)
        tmp_path = tf.name
        tf.write(pem_block)
        tf.flush()
        tf.close()

        # First try: -enddate (produces: notAfter=...)
        res = subprocess.run(
            ["openssl", "x509", "-noout", "-enddate", "-in", tmp_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        if res.returncode == 0:
            line = res.stdout.decode("utf-8", "ignore").strip()
            # Expected: notAfter=Jun  7 12:00:00 2027 GMT
            _, _, date_str = line.partition("=")
            return date_str.strip()

        # Fallback: -text and parse 'Not After' or 'Not Valid After'
        res2 = subprocess.run(
            ["openssl", "x509", "-noout", "-text", "-in", tmp_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        if res2.returncode == 0:
            text = res2.stdout.decode("utf-8", "ignore")
            m2 = re.search(r"Not\s+(?:Valid\s+)?After\s*:\s*(.+)", text, re.IGNORECASE)
            if m2:
                return m2.group(1).strip()

        return ""
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

def ensure_openssl_available():
    """Ensure openssl is available; exit with a clear error if not."""
    try:
        res = subprocess.run(["openssl", "version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if res.returncode != 0:
            print("Warning: 'openssl' returned a non-zero exit. Certificate parsing may fail.")
    except FileNotFoundError:
        print("Error: 'openssl' not found on PATH. Please install OpenSSL and try again.")
        sys.exit(1)

def main():
    # set up argument parser (argparse; optparse is deprecated)
    parser = argparse.ArgumentParser(
        description="Generate a macOS .mobileconfig containing the latest DoD PKI certificates."
    )
    parser.add_argument(
        "--removal-allowed", "-r",
        action="store_true",
        default=False,
        help="Specifies that the profile can be removed."
    )
    parser.add_argument(
        "--organization",
        default="",
        help="Cosmetic name for the organization deploying the profile."
    )
    parser.add_argument(
        "--output", "-o",
        metavar="PATH",
        help="Output path for profile. Defaults to '<display_name>.mobileconfig' in the current working directory."
    )
    parser.add_argument(
        "--export-certs", "-e",
        action="store_true",
        default=False,
        help="If set, save individual certs into ./certs/<profile> as PEM files."
    )
    parser.add_argument(
        "--skip-expired", "-x",
        action="store_true",
        default=None,  # None => use SKIP_EXPIRED top-level toggle
        help="Skip expired certificates (defaults to SKIP_EXPIRED if not provided)."
    )
    parser.add_argument(
        "--source",
        default="config",
        help="Which set(s): 'dod', 'wcf', 'jitc', 'eca', 'both', 'all', or 'config' (default, uses ENABLED_SOURCES)."
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Network timeout in seconds when downloading the ZIP (default: 30)."
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=3,
        help="Retry count for downloading the ZIP (default: 3)."
    )
    options = parser.parse_args()

    # Ensure OpenSSL is available before doing anything heavy
    ensure_openssl_available()

    # Resolve skip_expired from CLI or top-level toggle
    skip_expired = options.skip_expired if options.skip_expired is not None else SKIP_EXPIRED

    # Source selection with top-level toggles
    selected = (options.source or "config").strip().lower()
    valid = {"dod", "wcf", "jitc", "eca", "both", "all", "config"}
    if selected not in valid:
        print(f"Unknown --source '{options.source}'. Use one of: {', '.join(sorted(valid))}.")
        sys.exit(2)

    if selected == "config":
        sources = [s for s in ENABLED_SOURCES if s in SOURCES]
    elif selected == "both":
        sources = ["dod", "wcf"]
    elif selected == "all":
        sources = list(SOURCES.keys())
    else:
        sources = [selected]

    if not sources:
        print("No sources selected. Adjust ENABLED_SOURCES or pass --source.")
        sys.exit(2)

    if options.output and len(sources) > 1:
        print("Note: --output is ignored when processing multiple sources. Separate files will be generated.")

    for src in sources:
        # create working directory
        tempdir = tempfile.mkdtemp()
        try:
            pem_file = tempdir + "/bundle.txt"
            pem_file_prefix = tempdir + "/Cert-"  # kept for reference, we use a per-bundle prefix below

            src_def = SOURCES[src]
            zip_url = src_def["zip_url"]
            context = ssl._create_unverified_context()

            print(f"\n[{src.upper()}] Attempting to get .zip file from {zip_url}")

            # Use the new robust downloader without diff markers
            zip_filename = extract_dod_cert_zip_file(zip_url, tempdir, timeout=options.timeout, retries=options.retries)

            # Attempt to get version from zip filename first
            bundle_version = extract_bundle_version(zip_filename)

            # extract the certificates in .pem format from the p7b files
            pem_bundle_files, pem_title, dir_version = find_p7b_file(tempdir, title_hint=src_def["profile_title"])
            if dir_version != "unknown":
                bundle_version = dir_version

            print("\nProcessing certificate bundles...")
            # Aggregate from PKCS#7 and PEM-like files
            cert_datas = []
            pkcs7_blocks_total = 0
            if pem_bundle_files:
                for pem_bundle_file in pem_bundle_files:
                    bundle_name = os.path.basename(pem_bundle_file)
                    print(f"\nExtracting certificates from: {bundle_name}")
                    proc = subprocess.run(
                        ["openssl", "pkcs7", "-in", pem_bundle_file, "-inform", "der", "-print_certs", "-out", pem_file],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE
                    )
                    if proc.returncode != 0:
                        err = proc.stderr.decode("utf-8", "ignore").strip()
                        print(f"Warning: openssl pkcs7 failed for {bundle_name}: {err}")
                        continue
                    try:
                        with open(pem_file, "r", errors="ignore") as f:
                            content = f.read()
                        blocks = extract_cert_blocks(content)
                        if blocks:
                            cert_datas.extend(blocks)
                            pkcs7_blocks_total += len(blocks)
                            print(f"  - Found {len(blocks)} certificates")
                        else:
                            print("  - No certificates found in this bundle output.")
                    except Exception as e:
                        print(f"Warning: failed to parse PKCS#7 output: {e}")
            else:
                print("No PKCS#7 bundles to process.")

            # setup output file
            if options.output and len(sources) == 1:
                output_file = options.output
                display_name = os.path.splitext(os.path.basename(output_file))[0]
            else:
                script_dir = os.path.dirname(os.path.abspath(__file__))
                display_name = f"{src_def['display_prefix']}_V{bundle_version}"
                output_file = os.path.join(script_dir, f"{display_name}.mobileconfig")
        
            print("\nStarting certificate processing...")
            print(f"Output file will be: {output_file}")

            description = (
                f"{src_def['description_prefix']}\n\n"
                f"This configuration profile was generated using a Python script.\n\n"
                f"Last Updated: {datetime.now().strftime('%Y-%m-%d')}\n"
                f"File Version: {bundle_version}\n"
                f"Script Developer: github.com/cocopuff2u\n"
                f"Script Version: {SCRIPT_VERSION}"
            )

            newPayload = ConfigurationProfile(
                identifier=pem_title,
                uuid=False,
                removal_allowed=options.removal_allowed,
                organization=options.organization,
                displayname=display_name,
                export=options.export_certs,
            )
            newPayload.data["PayloadDescription"] = description

            # From PEM-like files directly in the archive (do NOT reset cert_datas here)
            pem_like_files = find_pem_files(tempdir)
            if pem_like_files:
                total_blocks = 0
                for fpath in pem_like_files:
                    try:
                        with open(fpath, "r", errors="ignore") as f:
                            content = f.read()
                        blocks = extract_cert_blocks(content)
                        if blocks:
                            cert_datas.extend(blocks)
                            total_blocks += len(blocks)
                    except Exception:
                        continue
                print(f"Found {total_blocks} PEM certificate blocks across {len(pem_like_files)} PEM-like files")
            else:
                print("No PEM-like files found in the archive.")

            # Print PKCS#7 block count after the PEM-like section
            if pkcs7_blocks_total:
                print(f"Found {pkcs7_blocks_total} PEM certificate blocks from PKCS#7 bundles")

            if not cert_datas:
                print("Error: No certificates found to process (no PKCS#7 output and no PEM blocks).")
                sys.exit(1)

            print("Processing certificates in sorted order...")
            cert_datas.sort()

            imported_self_signed = 0
            imported_non_self_signed = 0
            expired_skipped = 0
            
            for certData in cert_datas:
                # Always compute CN/issuer from certificate block for correctness
                subj_cn, iss_cn = parse_subject_issuer_from_pem(certData)
                cn = subj_cn or "Unknown CN"
                issuer_cn = iss_cn or ""

                # Optionally skip expired certificates
                if skip_expired and cert_is_expired(certData):
                    not_after_str = get_cert_not_after(certData) or "unknown"
                    print(f"Skipping expired certificate: {cn} (Not Valid After: {not_after_str})")
                    expired_skipped += 1
                    continue

                is_self_signed = bool(cn and issuer_cn and cn == issuer_cn)
                newPayload.addPayloadFromPEM(certData)
                if is_self_signed:
                    imported_self_signed += 1
                else:
                    imported_non_self_signed += 1

            print(f"\nSummary for {src.upper()}:")
            print(f"- Self-signed certificates: {imported_self_signed}")
            print(f"- Non-self-signed certificates: {imported_non_self_signed}")
            if skip_expired:
                print(f"- Expired certificates skipped: {expired_skipped}")
            # Use processed_hashes for true unique count
            print(f"- Total unique certificates: {len(newPayload.processed_hashes)}")
            print(f"\nSaving configuration profile to: {output_file}")
            
            newPayload.finalizeAndSave(output_file)
            print("Configuration profile creation complete!")
        finally:
            # Ensure no temp data can bleed into another run/source
            try:
                shutil.rmtree(tempdir)
            except Exception:
                pass

if __name__ == "__main__":
    main()
