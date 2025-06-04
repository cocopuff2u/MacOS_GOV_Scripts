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
#
####################################################################################################

SCRIPT_VERSION = "1.0"

import base64
import io
import optparse
import os
import os.path
import re
import ssl
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from datetime import datetime
from html.parser import HTMLParser
from pathlib import Path
from plistlib import dump
from urllib.parse import urlparse
from uuid import uuid4


class URLHtmlParser(HTMLParser):
    links = []

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
        self.processed_certs = set()  # Track processed certificates

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
        payload_dict["PayloadCertificateFileName"] = certname + ".cer"
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

        name_regex_pattern = r"(^subject.*)((CN\s?=\s?)(.*))"  # Added r-prefix
        name_regex = re.compile(name_regex_pattern, flags=re.MULTILINE)
        name = name_regex.search(pemfile).group(4)

        # Skip if we've already processed this cert
        if name in self.processed_certs:
            print(f"Skipping duplicate certificate: {name}")
            return

        self.processed_certs.add(name)

        issuer_regex_pattern = r"(^issuer.*)((CN\s?=\s?)(.*))"  # Added r-prefix
        issuer_regex = re.compile(issuer_regex_pattern, flags=re.MULTILINE)
        issuer = issuer_regex.search(pemfile).group(4)

        # get type
        if issuer == name:
            certtype = "root"
        else:
            certtype = "intermediate"

        print(f"Adding {name} to profile...")
        self._addCertificatePayload(bytes(payload_content_bytes), name, certtype)

        # write PEM to file
        if self.export:
            print(f"Writing {name}.pem to certs folder...")
            self._writePEMtoFile(pemfile, name)

    def _writePEMtoFile(self, pemfile, name):
        Path("./certs").mkdir(parents=True, exist_ok=True)
        output_path = f"./certs/{name}.pem"
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
    print >> sys.stderr, errmsg
    exit(-1)


def extract_dod_cert_url(content):
    """Takes the html content and parses the href tags to collect links.  Looks for the DoD.zip in the links and returns that URL"""
    parser = URLHtmlParser()
    parser.feed(content)
    for url in parser.links:
        if "DoD.zip" in url:
            return url
    return


def extract_dod_cert_zip_file(zip_url, tempdir):
    """Takes the URL to the .zip file and extracts the contents to a temp directory.  Returns the location of the .pem file for processing"""
    context = ssl._create_unverified_context()
    r = urllib.request.urlopen(url=zip_url, context=context)
    zip_filename = os.path.basename(urlparse(zip_url).path)
    z = zipfile.ZipFile(io.BytesIO(r.read()))
    z.extractall(tempdir)
    return zip_filename


def find_p7b_file(tempdir):
    """Attempts to return paths to all pkcs7 bundle files, prioritizing Root CA files"""
    root_p7b_files = []
    other_p7b_files = []
    bundle_version = "unknown"
    
    # Get version from directory name
    for dirpath, subdir, files in os.walk(tempdir):
        dirname = os.path.basename(dirpath)
        version_match = re.search(r'Certificates_PKCS7_v(\d+_\d+)_', dirname, re.IGNORECASE)
        if version_match:
            # Replace underscore with dot in version
            bundle_version = version_match.group(1).replace('_', '.')
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
        print("Warning: No .p7b files found!")
        sys.exit(1)
        
    print(f"Found {len(root_p7b_files)} Root CA bundles and {len(other_p7b_files)} other certificate bundles")
    return root_p7b_files + other_p7b_files, "DoD_PKI_Chain", bundle_version


def main():
    # set up argument parser
    parser = optparse.OptionParser()
    parser.set_usage(
        """usage: %prog [options]
       Run '%prog --help' for more information."""
    )

    # Optionals
    parser.add_option(
        "--removal-allowed",
        "-r",
        action="store_true",
        default=False,
        help="""Specifies that the profile can be removed.""",
    )
    parser.add_option(
        "--organization",
        action="store",
        default="",
        help="Cosmetic name for the organization deploying the profile.",
    )
    parser.add_option(
        "--output",
        "-o",
        action="store",
        metavar="PATH",
        help="Output path for profile. Defaults to '<name of DOD Cert file>.mobileconfig' in the current working directory.",
    )
    parser.add_option(
        "--export-certs",
        "-e",
        action="store_true",
        default=False,
        help="""If set, will save individual certs into a ./certs folder.""",
    )

    options, args = parser.parse_args()

    if len(args):
        parser.print_usage()
        sys.exit(-1)

    # create working directory
    tempdir = tempfile.mkdtemp()
    pem_file = tempdir + "/dod.txt"
    pem_file_prefix = tempdir + "/DoD_CA-"

    # URL to the DOD PKE library, will parse its contents to locate the .zip file to process
    pke_library_url = "https://public.cyber.mil/pki-pke/pkipke-document-library/"
    context = ssl._create_unverified_context()

    pke_site_contents = urllib.request.urlopen(url=pke_library_url, context=context)

    pke_bytes = pke_site_contents.read()
    pke_site_contents_string = pke_bytes.decode("utf8")
    pke_site_contents.close()

    certificate_url = extract_dod_cert_url(pke_site_contents_string)
    print(f"Attempting to get .zip file from {certificate_url}")

    zip_filename = extract_dod_cert_zip_file(certificate_url, tempdir)
    bundle_version = "unknown"
    version_match = re.search(r'certificates_pkcs7_v(\d+_\d+)_', zip_filename, re.IGNORECASE)
    if version_match:
        bundle_version = version_match.group(1)

    # extract the certificates in .pem format from the p7b files
    pem_bundle_files, pem_title, bundle_version = find_p7b_file(tempdir)
    
    print("\nProcessing certificate bundles...")
    for pem_bundle_file in pem_bundle_files:
        is_root = "Root_CA" in pem_bundle_file
        bundle_name = os.path.basename(pem_bundle_file)
        print(f"\nExtracting certificates from: {bundle_name}")
        
        process = subprocess.Popen(
            ["openssl", "pkcs7", "-in", pem_bundle_file, "-inform", "der", 
             "-print_certs", "-out", pem_file],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            shell=False
        )
        process.communicate()

        # Split into individual certificates
        split_process = subprocess.Popen(
            ["split", "-p", "subject=", pem_file, pem_file_prefix],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            shell=False
        )
        split_process.communicate()

    # setup output file
    if options.output:
        output_file = options.output
    else:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        date_str = datetime.now().strftime('%Y%m%d')
        display_name = f"DoD_Certificates_V{bundle_version}"
        output_file = os.path.join(script_dir, f"{display_name}.mobileconfig")
    
    print("\nStarting certificate processing...")
    print(f"Output file will be: {output_file}")

    description = (
        f"Latest DoD Certificates from https://public.cyber.mil\n\n"
        f"This configuration profile was generated using a Python script.\n\n"
        f"Last Updated: {datetime.now().strftime('%Y-%m-%d')}\n"
        f"File Version: {bundle_version}\n"
        f"Script Developer: github.com/cocopuff2u\n"
        f"Script Version: {SCRIPT_VERSION}"
    )

    display_name = os.path.splitext(os.path.basename(output_file))[0]
    newPayload = ConfigurationProfile(
        identifier=pem_title,
        uuid=False,
        removal_allowed=options.removal_allowed,
        organization=options.organization,
        displayname=display_name,
        export=options.export_certs,
    )
    newPayload.data["PayloadDescription"] = description

    # Sort certificates to prioritize root CAs
    cert_files = []
    for cert in os.listdir(tempdir):
        if cert.startswith("DoD_CA-"):
            cert_files.append(cert)
    
    print(f"\nFound {len(cert_files)} certificate files to process")
    
    # Sort to ensure root CAs are processed first
    cert_files.sort()
    print("Processing certificates in sorted order...")

    self_signed_count = 0
    non_self_signed_count = 0
    
    # Process all DoD certificate files
    for cert in cert_files:
        with open(os.path.join(tempdir, cert), "r") as f:
            certData = f.read()
            # Check if self-signed by comparing subject and issuer
            name_match = re.search(r"subject.*?CN\s?=\s?(.*?)(?:\n|$)", certData)
            issuer_match = re.search(r"issuer.*?CN\s?=\s?(.*?)(?:\n|$)", certData)
            if name_match and issuer_match and name_match.group(1) == issuer_match.group(1):
                self_signed_count += 1
            else:
                non_self_signed_count += 1
            newPayload.addPayloadFromPEM(certData)

    print(f"\nSummary:")
    print(f"- Self-signed certificates: {self_signed_count}")
    print(f"- Non-self-signed certificates: {non_self_signed_count}")
    print(f"- Total unique certificates: {len(newPayload.processed_certs)}")
    print(f"\nSaving configuration profile to: {output_file}")
    
    newPayload.finalizeAndSave(output_file)
    print("Configuration profile creation complete!")


if __name__ == "__main__":
    main()
