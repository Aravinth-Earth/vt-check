"""Tool schemas — descriptions are what the model reads when deciding to call a tool."""

CHECK_FILE = {
    "name": "vt_check_file",
    "description": (
        "Check a file downloaded from the internet BEFORE opening or extracting it, by hashing it "
        "locally and looking the SHA-256 up in VirusTotal. The file itself is never uploaded. "
        "Also inspects archives in memory: path traversal, decompression bombs, encrypted entries, "
        "executables and double extensions inside a zip, and nested archives up to depth 3. "
        "Use when the user asks 'is this file/zip safe?', 'check this download for virus or malware', "
        "or wants a safety verdict before running an installer, .deb, .AppImage or script."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "Path to the file to check (absolute, or ~-relative is accepted).",
            },
        },
        "required": ["path"],
    },
}

CHECK_URL = {
    "name": "vt_check_url",
    "description": (
        "Check whether a link is malicious or phishing using a READ-ONLY VirusTotal lookup — "
        "nothing is submitted, so looking something up does not publish it. "
        "Returns engine detections, category labels and reputation. 'unknown' means VirusTotal has "
        "never seen that URL, which is not the same as safe. "
        "Pass submit=true ONLY when the user explicitly wants the URL queued for scanning; that "
        "publishes the URL to VirusTotal. "
        "Use when the user pastes a link and asks if it is safe, legit, phishing or malware."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "Full URL (https://…) or a bare domain."},
            "submit": {
                "type": "boolean",
                "default": False,
                "description": "Submit the URL for a new VirusTotal scan if unseen. Discloses the URL publicly.",
            },
        },
        "required": ["url"],
    },
}

STATUS = {
    "name": "vt_status",
    "description": (
        "Report whether the VirusTotal API key is configured and valid, plus free-tier limits "
        "(4 requests/min, 500/day) and the configured cache TTL. Use when a check fails with "
        "'no_api_key' or an auth error, or when the user asks how to add or verify their key."
    ),
    "parameters": {"type": "object", "properties": {}},
}
