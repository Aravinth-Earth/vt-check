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
        "Check a link, a domain, or an IP address with VirusTotal using a READ-ONLY lookup — nothing "
        "is submitted, so looking something up does not publish it. Routes automatically: full URLs go "
        "to /urls, bare domains to /domains, IPs to /ip_addresses. Defanged indicators are accepted "
        "('hxxps://evil[.]com', '1.2.3[.]4'). Returns engine detections, category labels, reputation, "
        "and for IPs the AS owner/country. 'unknown' means VirusTotal has never seen it, which is not "
        "the same as safe. Set submit=true ONLY when the user explicitly wants a URL queued for "
        "scanning; that publishes the URL. Use for 'is this link safe?', 'is this domain legit?', "
        "'check this IP', phishing checks."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": "Full URL (https://…), a bare domain, or an IP address.",
            },
            "submit": {
                "type": "boolean",
                "default": False,
                "description": "Submit a URL for a new VirusTotal scan if unseen. Discloses the URL publicly.",
            },
        },
        "required": ["url"],
    },
}

CHECK_IP = {
    "name": "vt_check_ip",
    "description": (
        "Look up an IPv4/IPv6 address in VirusTotal (read-only): engine detections, AS owner, country "
        "and network. Use when the user gives an explicit IP and asks whether it is malicious, a "
        "scanner, a botnet host, or just wants IP reputation. For links and domains use vt_check_url."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "ip": {"type": "string", "description": "IPv4 or IPv6 address, e.g. 8.8.8.8"},
        },
        "required": ["ip"],
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
