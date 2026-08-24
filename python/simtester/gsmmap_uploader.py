"""Port of de.srlabs.simtester.GSMMapUploader.

Uses `requests` with the system trust store instead of replicating the
bundled Java keystore/truststore dance.
"""

from __future__ import annotations

import os

from simlib.logging_utils import format_debug_message

UPLOAD_URL = "https://gsmmap.srlabs.de:4433/cgi-bin/dat_upload.cgi"


def upload_file(filename: str | None) -> bool:
    if not filename:
        raise ValueError(format_debug_message("filename cannot be empty nor null."))

    if not os.path.exists(filename):
        raise ValueError(format_debug_message(f"file {filename} does not exists!"))

    print("Trying to upload data to gsmmap.org ..")

    try:
        import requests
    except ImportError:
        print("The 'requests' package is required for GSM Map upload (pip install requests)")
        return False

    filename_without_ext = os.path.splitext(os.path.basename(filename))[0]

    try:
        with open(filename, "rb") as f:
            files = {"bursts": (os.path.basename(filename), f, "application/octet-stream")}
            data = {"ident": filename_without_ext, "submit": "batch", "opaque": "1"}
            response = requests.post(UPLOAD_URL, files=files, data=data, timeout=60)

        if response.status_code != 200:
            print(f"Upload has failed, status is: {response.status_code}")
            return False

        return response.text.strip() == "OK"
    except Exception as e:
        print("There was a problem during upload: ")
        print(e)
        return False
