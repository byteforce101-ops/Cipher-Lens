"""
Config parser for ipsec.conf, strongSwan, libreswan, and general IPsec VPN configuration files.
"""

import re
from typing import Any, Dict


def parse_config_file(content: str, filename: str) -> Dict[str, Any]:
    """
    Parses configuration content and extracts key IPsec cryptographic and operational parameters.
    """
    parsed: Dict[str, Any] = {
        "file_type": "config",
        "filename": filename,
        "connections": {},
        "raw_text": content,
        "parameters": {
            "keyexchange": "ikev2",
            "ike_proposals": [],
            "esp_proposals": [],
            "auth_method": "preshared_key",
            "psk": None,
            "aggressive_mode": False,
            "pfs": True,
            "dpd_delay": None,
            "dpd_action": None,
            "lifetime": None,
            "dh_groups": [],
            "ciphers": [],
            "hashes": [],
        },
        "technical_snippet": "",
    }

    lines = [line.strip() for line in content.splitlines() if line.strip() and not line.strip().startswith("#")]
    current_conn = "default"

    for line in lines:
        conn_match = re.match(r"^conn\s+([\w\.\-]+)", line, re.IGNORECASE)
        if conn_match:
            current_conn = conn_match.group(1)
            parsed["connections"][current_conn] = {}
            continue

        if "=" in line:
            parts = line.split("=", 1)
            key = parts[0].strip().lower()
            val = parts[1].strip()
            if current_conn in parsed["connections"]:
                parsed["connections"][current_conn][key] = val

            # Normalize parameters
            if key in ["keyexchange", "ikev"]:
                parsed["parameters"]["keyexchange"] = val.lower()
            elif key == "ike":
                parsed["parameters"]["ike_proposals"].append(val)
                parsed["parameters"]["ciphers"].extend(re.findall(r"(aes[\w\-]*|3des|des|blowfish|chacha20)", val, re.IGNORECASE))
                parsed["parameters"]["hashes"].extend(re.findall(r"(sha1|sha256|sha384|sha512|md5)", val, re.IGNORECASE))
                parsed["parameters"]["dh_groups"].extend(re.findall(r"(modp\d+|dh\d+|group\d+)", val, re.IGNORECASE))
            elif key == "esp":
                parsed["parameters"]["esp_proposals"].append(val)
                parsed["parameters"]["ciphers"].extend(re.findall(r"(aes[\w\-]*|3des|des|blowfish|chacha20)", val, re.IGNORECASE))
                parsed["parameters"]["hashes"].extend(re.findall(r"(sha1|sha256|sha384|sha512|md5)", val, re.IGNORECASE))
                parsed["parameters"]["dh_groups"].extend(re.findall(r"(modp\d+|dh\d+|group\d+)", val, re.IGNORECASE))
            elif key in ["authby", "auth"]:
                if "secret" in val.lower() or "psk" in val.lower():
                    parsed["parameters"]["auth_method"] = "preshared_key"
                elif "pubkey" in val.lower() or "rsa" in val.lower() or "ecdsa" in val.lower():
                    parsed["parameters"]["auth_method"] = "public_key"
            elif key in ["aggressive", "aggressive-mode"]:
                parsed["parameters"]["aggressive_mode"] = val.lower() in ["yes", "true", "1", "enable", "enabled"]
            elif key in ["pfs"]:
                parsed["parameters"]["pfs"] = val.lower() in ["yes", "true", "1"]
            elif key in ["dpddelay", "dpd_delay"]:
                parsed["parameters"]["dpd_delay"] = val
            elif key in ["dpdaction", "dpd_action"]:
                parsed["parameters"]["dpd_action"] = val
            elif key in ["lifetime", "ikelifetime", "salifetime"]:
                parsed["parameters"]["lifetime"] = val

        # Check for pre-shared keys defined directly or in ipsec.secrets
        psk_match = re.search(r'(?:psk|secret|key)\s*[:=]\s*["\']?([^"\'\s]+)["\']?', line, re.IGNORECASE)
        if psk_match:
            parsed["parameters"]["psk"] = psk_match.group(1)

    # Format a concise technical snippet for the UI code box
    snippet_lines = []
    if parsed["connections"]:
        for cname, attrs in list(parsed["connections"].items())[:2]:
            snippet_lines.append(f"conn {cname}")
            for k, v in list(attrs.items())[:6]:
                snippet_lines.append(f"  {k} = {v}")
    if not snippet_lines:
        snippet_lines = lines[:10]

    parsed["technical_snippet"] = "\n".join(snippet_lines) if snippet_lines else content[:300]
    return parsed
