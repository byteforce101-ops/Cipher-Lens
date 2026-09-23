"""
Security rule engine for IPsec/IKE configurations and packet captures.
Audits configuration parameters against NIST SP 800-77, NSA, and RFC best practices.
"""

from typing import Any, Dict, List


def evaluate_rules(parsed_data: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Evaluates parsed IPsec parameters and produces structured findings.
    Each finding matches the frontend schema:
    {
      "severity": "Critical" | "High" | "Medium" | "Low",
      "title": str,
      "category": str,
      "explanation": str,
      "detected": str,
      "recommended": str
    }
    """
    params = parsed_data.get("parameters", {})
    findings: List[Dict[str, str]] = []

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
            })
    else:
        # Default placeholder/auditing finding if no PSK provided
        if params.get("auth_method") == "preshared_key":
            findings.append({
                "severity": "Critical",
                "title": "Pre-shared key authentication with low entropy",
                "category": "Authentication",
                "explanation": "Pre-shared key authentication is configured without strong key rotation policies or verifiable entropy guarantees.",
                "detected": "psk / secret",
                "recommended": "Migrate to X.509 RSA/ECDSA certificates or 32+ char random secrets",
            })

    # 2. Check for IKEv1 or Aggressive Mode
    keyexchange = params.get("keyexchange", "ikev2").lower()
    aggressive = params.get("aggressive_mode", False)
    if aggressive or keyexchange in ["ikev1", "ike"]:
        findings.append({
            "severity": "High",
            "title": "Aggressive mode or legacy IKEv1 enabled",
            "category": "IKE negotiation",
            "explanation": "IKEv1 and aggressive mode expose identity hashes in cleartext during initial handshake packets, making them susceptible to sniffing and cracking.",
            "detected": "aggressive-mode / ikev1",
            "recommended": "Enforce IKEv2 Main Mode with cryptographic identity protection",
        })

    # 3. Check for Weak Ciphers (3DES, DES, Blowfish)
    ciphers = [c.lower() for c in params.get("ciphers", [])]
    detected_weak_cipher = None
    for c in ciphers:
        if "3des" in c or "des" in c or "blowfish" in c:
            detected_weak_cipher = c
            break

    if detected_weak_cipher:
        findings.append({
            "severity": "Medium",
            "title": "Legacy encryption proposal enabled",
            "category": "Cryptography",
            "explanation": "3DES and 64-bit block ciphers are deprecated due to Sweet32 collision vulnerabilities and poor performance.",
            "detected": detected_weak_cipher,
            "recommended": "Enforce AES-256-GCM or ChaCha20-Poly1305 with AEAD",
        })
    else:
        # Check if AEAD is used
        has_gcm = any("gcm" in c for c in ciphers)
        if not has_gcm and ciphers:
            findings.append({
                "severity": "Medium",
                "title": "Non-AEAD cipher in proposal set",
                "category": "Cryptography",
                "explanation": "Legacy cipher suites separate encryption and authentication rather than using authenticated encryption.",
                "detected": ciphers[0] if ciphers else "aes-cbc",
                "recommended": "Upgrade proposal to AES-256-GCM (RFC 4106)",
            })

    # 4. Check Diffie-Hellman Groups
    dh_groups = [str(g).lower() for g in params.get("dh_groups", [])]
    weak_dh = None
    for dh in dh_groups:
        if any(w in dh for w in ["modp1024", "modp768", "group1", "group2", "group5"]):
            weak_dh = dh
            break

    if weak_dh:
        findings.append({
            "severity": "High",
            "title": "Weak Diffie-Hellman group (< 2048-bit)",
            "category": "Key Exchange",
            "explanation": "Diffie-Hellman groups 1, 2, and 5 offer less than 112 bits of security and are vulnerable to well-resourced state adversaries.",
            "detected": weak_dh,
            "recommended": "Enforce DH Group 14 (2048-bit MODP), Group 19 (256-bit ECP), or Group 21",
        })

    # 5. Check Dead Peer Detection (DPD)
    dpd_delay = params.get("dpd_delay")
    if dpd_delay:
        # Extract digits
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
            })
    else:
        findings.append({
            "severity": "Low",
            "title": "DPD interval unverified or default",
            "category": "Availability",
            "explanation": "Explicit Dead Peer Detection parameters should be configured to prevent blackholing VPN traffic.",
            "detected": "default / unconfigured",
            "recommended": "Specify dpddelay=30s and dpdaction=restart",
        })

    return findings
