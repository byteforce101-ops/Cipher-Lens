"""
Security rule engine for IPsec/IKE configurations and packet captures.
Audits configuration parameters against NIST SP 800-77, IETF RFC 8247, PCI-DSS, and CIS benchmarks.
"""

from typing import Any, Dict, List
import re
try:
    from engine.remediations import (
        TAG_NIST,
        TAG_PCIDSS,
        TAG_RFC,
        TAG_FIPS,
        TAG_CIS,
        TAG_ANSSI,
        TAG_BSI,
        TAG_RFC3706,
        get_cipher_remediation,
        get_dh_remediation,
        get_hash_remediation,
    )
except ImportError:
    from .remediations import (
        TAG_NIST,
        TAG_PCIDSS,
        TAG_RFC,
        TAG_FIPS,
        TAG_CIS,
        TAG_ANSSI,
        TAG_BSI,
        TAG_RFC3706,
        get_cipher_remediation,
        get_dh_remediation,
        get_hash_remediation,
    )


def evaluate_rules(parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Evaluates parsed IPsec parameters and produces structured findings.
    Each finding conforms to:
    {
      "severity": "Critical" | "High" | "Medium" | "Low",
      "title": str,
      "category": str,
      "explanation": str,
      "detected": str,
      "recommended": str,
      "detected_config_line": str,
      "recommended_config_line": str,
      "compliance_tags": List[str]
    }
    """
    params = parsed_data.get("parameters", {})
    findings: List[Dict[str, Any]] = []

    ike_props = params.get("ike_proposals", [])
    esp_props = params.get("esp_proposals", [])
    raw_ike_sample = f"ike={ike_props[0]}" if ike_props else ""
    raw_esp_sample = f"esp={esp_props[0]}" if esp_props else ""

    # 1. Check for Weak Pre-Shared Key (PSK)
    psk = params.get("psk")
    if psk:
        if len(psk) < 20 or any(common in psk.lower() for common in ["vpn", "key", "secret", "admin", "123"]):
            findings.append({
                "severity": "Critical",
                "title": "Weak pre-shared key detected",
                "category": "Authentication",
                "explanation": "The configured pre-shared key is short or predictable, leaving the tunnel vulnerable to offline dictionary attacks.",
                "detected": psk if len(psk) <= 24 else f"{psk[:10]}...",
                "recommended": "Use a 32+ character high-entropy random secret or PKI certificates",
                "detected_config_line": f'authby=secret\npsk="{psk}"',
                "recommended_config_line": 'authby=pubkey\n# Or high-entropy secret:\npsk="s8V#9mK2$pL9@zX4!qW7&vB1^nC3*jY5"',
                "compliance_tags": [TAG_NIST, TAG_PCIDSS, TAG_CIS],
            })
    else:
        # Auditing finding if generic preshared key auth is configured
        if params.get("auth_method") == "preshared_key":
            findings.append({
                "severity": "Critical",
                "title": "Pre-shared key authentication with low entropy",
                "category": "Authentication",
                "explanation": "Pre-shared key authentication is configured without strong key rotation policies or verifiable entropy guarantees.",
                "detected": "psk / secret",
                "recommended": "Migrate to X.509 RSA/ECDSA certificates or 32+ char random secrets",
                "detected_config_line": "authby=secret",
                "recommended_config_line": "authby=pubkey\n# Enforce X.509 ECDSA or RSA-3072+ certificates",
                "compliance_tags": [TAG_NIST, TAG_PCIDSS, TAG_CIS],
            })

    # 2. Check for IKEv1 or Aggressive Mode
    keyexchange = str(params.get("keyexchange", "ikev2")).lower()
    aggressive = params.get("aggressive_mode", False)
    if aggressive or keyexchange in ["ikev1", "ike"]:
        detected_lines = []
        if keyexchange in ["ikev1", "ike"]:
            detected_lines.append("keyexchange=ikev1")
        if aggressive:
            detected_lines.append("aggressive=yes")
        detected_cfg = "\n".join(detected_lines) if detected_lines else "keyexchange=ikev1"

        findings.append({
            "severity": "High",
            "title": "Aggressive mode or legacy IKEv1 enabled",
            "category": "IKE negotiation",
            "explanation": "IKEv1 and aggressive mode expose identity hashes in cleartext during initial handshake packets, making them susceptible to sniffing and cracking.",
            "detected": "aggressive-mode / ikev1" if aggressive else "ikev1",
            "recommended": "Enforce IKEv2 Main Mode with cryptographic identity protection",
            "detected_config_line": detected_cfg,
            "recommended_config_line": "keyexchange=ikev2\naggressive=no",
            "compliance_tags": [TAG_RFC, TAG_NIST, TAG_ANSSI],
        })

    # 3. Check for Weak Ciphers (3DES, DES, Blowfish)
    ciphers = [str(c).lower() for c in params.get("ciphers", [])]
    detected_weak_cipher = None
    for c in ciphers:
        if "3des" in c or "des" in c or "blowfish" in c:
            detected_weak_cipher = c
            break

    if detected_weak_cipher:
        rem = get_cipher_remediation(detected_weak_cipher)
        det_line = raw_ike_sample or f"ike={detected_weak_cipher}-sha1-modp1024!"
        rec_line = rem.get("recommended_ike", "ike=aes256gcm16-sha384-modp3072!")
        if raw_esp_sample and "3des" in raw_esp_sample.lower():
            det_line = raw_esp_sample
            rec_line = rem.get("recommended_esp", "esp=aes256gcm16-modp3072!")

        findings.append({
            "severity": "Medium",
            "title": "Legacy encryption proposal enabled",
            "category": "Cryptography",
            "explanation": f"{detected_weak_cipher.upper()} and 64-bit block ciphers are deprecated due to Sweet32 collision vulnerabilities and poor performance.",
            "detected": detected_weak_cipher,
            "recommended": rem.get("recommended", "Enforce AES-256-GCM or ChaCha20-Poly1305 with AEAD"),
            "detected_config_line": det_line,
            "recommended_config_line": rec_line,
            "compliance_tags": rem.get("compliance_tags", [TAG_NIST, TAG_PCIDSS, TAG_FIPS]),
        })
    else:
        # Check if AEAD is used
        has_gcm = any("gcm" in c or "chacha" in c for c in ciphers)
        if not has_gcm and ciphers:
            det_cipher = ciphers[0] if ciphers else "aes-cbc"
            det_line = raw_esp_sample or f"esp={det_cipher}-sha256"
            findings.append({
                "severity": "Medium",
                "title": "Non-AEAD cipher in proposal set",
                "category": "Cryptography",
                "explanation": "Legacy cipher suites separate encryption and authentication rather than using authenticated encryption (AEAD).",
                "detected": det_cipher,
                "recommended": "Upgrade proposal to AES-256-GCM (RFC 4106)",
                "detected_config_line": det_line,
                "recommended_config_line": "esp=aes256gcm16-modp3072!",
                "compliance_tags": [TAG_RFC, TAG_NIST],
            })

    # 4. Check Diffie-Hellman Groups
    dh_groups = [str(g).lower() for g in params.get("dh_groups", [])]
    weak_dh = None
    for dh in dh_groups:
        if any(w in dh for w in ["modp1024", "modp768", "group1", "group2", "group5", "dh1", "dh2", "dh5"]):
            weak_dh = dh
            break

    if weak_dh:
        dh_rem = get_dh_remediation(weak_dh)
        det_line = raw_ike_sample or f"ike=aes256-sha256-{weak_dh}"
        findings.append({
            "severity": "High",
            "title": "Weak Diffie-Hellman group (< 2048-bit)",
            "category": "Key Exchange",
            "explanation": "Diffie-Hellman groups 1, 2, and 5 offer less than 112 bits of security and are vulnerable to precomputation and logjam attacks.",
            "detected": weak_dh,
            "recommended": dh_rem.get("recommended", "Enforce DH Group 14 (2048-bit MODP), Group 19 (256-bit ECP), or Group 15 (3072-bit)"),
            "detected_config_line": det_line,
            "recommended_config_line": "ike=aes256gcm16-sha384-modp3072!",
            "compliance_tags": dh_rem.get("compliance_tags", [TAG_RFC, TAG_NIST, TAG_BSI]),
        })

    # 5. Check Integrity Hashes (MD5, SHA-1)
    hashes = [str(h).lower() for h in params.get("hashes", [])]
    weak_hash = None
    for h in hashes:
        if "md5" in h or "sha1" in h or h == "sha":
            weak_hash = h
            break

    if weak_hash:
        h_rem = get_hash_remediation(weak_hash)
        det_line = raw_esp_sample or raw_ike_sample or f"esp=aes256-{weak_hash}"
        findings.append({
            "severity": "High" if "md5" in weak_hash else "Medium",
            "title": f"Deprecated hash algorithm ({weak_hash.upper()})",
            "category": "Integrity",
            "explanation": f"{weak_hash.upper()} has known collision weaknesses and is not recommended for cryptographic integrity in IPsec.",
            "detected": weak_hash,
            "recommended": h_rem.get("recommended", "Enforce SHA-256, SHA-384, or AEAD cipher suites"),
            "detected_config_line": det_line,
            "recommended_config_line": "ike=aes256gcm16-sha384-modp3072!\nesp=aes256gcm16-modp3072!",
            "compliance_tags": h_rem.get("compliance_tags", [TAG_NIST, TAG_PCIDSS, TAG_RFC]),
        })

    # 6. Check Perfect Forward Secrecy (PFS)
    pfs = params.get("pfs", True)
    if pfs is False:
        findings.append({
            "severity": "High",
            "title": "Perfect Forward Secrecy (PFS) disabled",
            "category": "Key Management",
            "explanation": "Child SAs do not perform a fresh Diffie-Hellman exchange; compromising long-term keys exposes past session traffic.",
            "detected": "pfs=no",
            "recommended": "Enable PFS (pfs=yes) with DH Group 14+ or ECP 256/384",
            "detected_config_line": "pfs=no",
            "recommended_config_line": "pfs=yes\nesp=aes256gcm16-modp3072!",
            "compliance_tags": [TAG_NIST, TAG_PCIDSS, TAG_RFC],
        })

    # 7. Check SA Lifetime
    lifetime = params.get("lifetime")
    if lifetime:
        # Check if lifetime exceeds 28800s (8h) or 24h
        digits = "".join(filter(str.isdigit, str(lifetime)))
        is_hours = "h" in str(lifetime).lower()
        num_val = int(digits) if digits else 0
        if (is_hours and num_val > 8) or (not is_hours and num_val > 28800):
            findings.append({
                "severity": "Low",
                "title": "Excessive Security Association lifetime",
                "category": "Key Lifetime",
                "explanation": "Extended SA lifetimes increase exposure window and key reuse volume under a single session key.",
                "detected": f"{lifetime}",
                "recommended": "Restrict IKE SA lifetime to <= 8h and Child SA lifetime to <= 1-8h",
                "detected_config_line": f"ikelifetime={lifetime}\nsalifetime={lifetime}",
                "recommended_config_line": "ikelifetime=8h\nsalifetime=1h",
                "compliance_tags": [TAG_NIST, TAG_CIS],
            })

    # 8. Check Dead Peer Detection (DPD)
    dpd_delay = params.get("dpd_delay")
    dpd_action = params.get("dpd_action")
    if dpd_delay:
        digits = "".join(filter(str.isdigit, str(dpd_delay)))
        delay_sec = int(digits) if digits else 120
        if delay_sec > 90:
            findings.append({
                "severity": "Low",
                "title": "DPD interval is conservative",
                "category": "Availability",
                "explanation": f"The Dead Peer Detection interval ({delay_sec}s) may delay recovery when a tunnel endpoint unexpectedly drops.",
                "detected": f"{delay_sec} seconds",
                "recommended": "Set DPD interval between 30 and 60 seconds with dpdaction=restart",
                "detected_config_line": f"dpddelay={delay_sec}s\ndpdaction={dpd_action or 'restart'}",
                "recommended_config_line": "dpddelay=30s\ndpdaction=restart\ndpdtimeout=120s",
                "compliance_tags": [TAG_RFC3706, TAG_CIS],
            })
    else:
        findings.append({
            "severity": "Low",
            "title": "DPD interval unverified or default",
            "category": "Availability",
            "explanation": "Explicit Dead Peer Detection parameters should be configured to prevent blackholing VPN traffic.",
            "detected": "default / unconfigured",
            "recommended": "Specify dpddelay=30s and dpdaction=restart",
            "detected_config_line": "# dpddelay not explicitly defined",
            "recommended_config_line": "dpddelay=30s\ndpdaction=restart\ndpdtimeout=120s",
            "compliance_tags": [TAG_RFC3706, TAG_CIS],
        })

    return findings
