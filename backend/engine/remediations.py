"""
Remediation and compliance mapping engine for IPsec VPN configurations.
Based on NIST SP 800-77 (Rev 1), IETF RFC 8247, RFC 7296, PCI-DSS v4.0, FIPS 140-3, and CIS benchmarks.
"""

from typing import Any, Dict, List, Optional, Tuple

# Standardized Framework Tags
TAG_NIST = "NIST SP 800-77"
TAG_PCIDSS = "PCI-DSS 4.0"
TAG_RFC = "IETF RFC 8247"
TAG_FIPS = "FIPS 140-3"
TAG_CIS = "CIS Benchmark"
TAG_ANSSI = "ANSSI"
TAG_BSI = "BSI TR-02102"
TAG_RFC3706 = "IETF RFC 3706"

# Parameter Remediations Catalog
CIPHER_REMEDIATIONS: Dict[str, Dict[str, Any]] = {
    "3des": {
        "recommended": "AES-256-GCM (RFC 4106) with 16-octet ICV",
        "recommended_ike": "ike=aes256gcm16-sha384-modp3072!",
        "recommended_esp": "esp=aes256gcm16-modp3072!",
        "compliance_tags": [TAG_NIST, TAG_PCIDSS, TAG_FIPS],
        "rationale": "3DES is vulnerable to Sweet32 64-bit block collision attacks and disallowed under FIPS 140-3.",
    },
    "des": {
        "recommended": "AES-256-GCM (RFC 4106)",
        "recommended_ike": "ike=aes256gcm16-sha384-modp3072!",
        "recommended_esp": "esp=aes256gcm16-modp3072!",
        "compliance_tags": [TAG_NIST, TAG_PCIDSS, TAG_FIPS],
        "rationale": "Single DES key length (56-bit) is trivially breakable in minutes.",
    },
    "blowfish": {
        "recommended": "AES-256-GCM or ChaCha20-Poly1305",
        "recommended_ike": "ike=aes256gcm16-sha384-modp3072!",
        "recommended_esp": "esp=aes256gcm16-modp3072!",
        "compliance_tags": [TAG_NIST, TAG_PCIDSS],
        "rationale": "Blowfish uses 64-bit block size susceptible to collision attacks.",
    },
}

DH_GROUP_REMEDIATIONS: Dict[str, Dict[str, Any]] = {
    "modp768": {
        "name": "DH Group 1 (768-bit MODP)",
        "recommended": "DH Group 14 (2048-bit MODP) or Group 19 (256-bit ECP)",
        "recommended_ike": "ike=aes256gcm16-sha384-modp3072!",
        "compliance_tags": [TAG_RFC, TAG_NIST, TAG_BSI],
    },
    "group1": {
        "name": "DH Group 1 (768-bit MODP)",
        "recommended": "DH Group 14 (2048-bit MODP) or Group 19 (256-bit ECP)",
        "recommended_ike": "ike=aes256gcm16-sha384-modp3072!",
        "compliance_tags": [TAG_RFC, TAG_NIST, TAG_BSI],
    },
    "modp1024": {
        "name": "DH Group 2 (1024-bit MODP)",
        "recommended": "DH Group 14 (2048-bit MODP), Group 15 (3072-bit MODP), or Group 19 (256-bit ECP)",
        "recommended_ike": "ike=aes256gcm16-sha384-modp3072!",
        "compliance_tags": [TAG_RFC, TAG_NIST, TAG_BSI],
    },
    "group2": {
        "name": "DH Group 2 (1024-bit MODP)",
        "recommended": "DH Group 14 (2048-bit MODP), Group 15 (3072-bit MODP), or Group 19 (256-bit ECP)",
        "recommended_ike": "ike=aes256gcm16-sha384-modp3072!",
        "compliance_tags": [TAG_RFC, TAG_NIST, TAG_BSI],
    },
    "modp1536": {
        "name": "DH Group 5 (1536-bit MODP)",
        "recommended": "DH Group 14 (2048-bit MODP) or Group 15 (3072-bit MODP)",
        "recommended_ike": "ike=aes256gcm16-sha384-modp3072!",
        "compliance_tags": [TAG_RFC, TAG_NIST, TAG_BSI],
    },
    "group5": {
        "name": "DH Group 5 (1536-bit MODP)",
        "recommended": "DH Group 14 (2048-bit MODP) or Group 15 (3072-bit MODP)",
        "recommended_ike": "ike=aes256gcm16-sha384-modp3072!",
        "compliance_tags": [TAG_RFC, TAG_NIST, TAG_BSI],
    },
}

HASH_REMEDIATIONS: Dict[str, Dict[str, Any]] = {
    "md5": {
        "recommended": "HMAC-SHA-256, HMAC-SHA-384, or AEAD (AES-GCM)",
        "recommended_ike": "ike=aes256gcm16-sha384-modp3072!",
        "recommended_esp": "esp=aes256gcm16-modp3072!",
        "compliance_tags": [TAG_NIST, TAG_PCIDSS, TAG_FIPS],
    },
    "sha1": {
        "recommended": "HMAC-SHA-256, HMAC-SHA-384, or AEAD (AES-GCM)",
        "recommended_ike": "ike=aes256gcm16-sha384-modp3072!",
        "recommended_esp": "esp=aes256gcm16-modp3072!",
        "compliance_tags": [TAG_NIST, TAG_PCIDSS, TAG_RFC],
    },
}


def get_cipher_remediation(cipher: str) -> Dict[str, Any]:
    """Returns remediation details and compliance tags for a detected weak cipher."""
    cipher_lower = cipher.lower()
    for key, data in CIPHER_REMEDIATIONS.items():
        if key in cipher_lower:
            return data
    return {
        "recommended": "AES-256-GCM (RFC 4106)",
        "recommended_ike": "ike=aes256gcm16-sha384-modp3072!",
        "recommended_esp": "esp=aes256gcm16-modp3072!",
        "compliance_tags": [TAG_NIST, TAG_RFC],
    }


def get_dh_remediation(dh_group: str) -> Dict[str, Any]:
    """Returns remediation details and compliance tags for a weak Diffie-Hellman group."""
    dh_lower = str(dh_group).lower()
    for key, data in DH_GROUP_REMEDIATIONS.items():
        if key in dh_lower:
            return data
    return {
        "recommended": "DH Group 14 (2048-bit MODP) or Group 19 (256-bit ECP)",
        "recommended_ike": "ike=aes256gcm16-sha384-modp3072!",
        "compliance_tags": [TAG_RFC, TAG_NIST],
    }


def get_hash_remediation(hash_algo: str) -> Dict[str, Any]:
    """Returns remediation details and compliance tags for a weak integrity hash algorithm."""
    h_lower = hash_algo.lower()
    for key, data in HASH_REMEDIATIONS.items():
        if key in h_lower:
            return data
    return {
        "recommended": "HMAC-SHA-256 or SHA-384",
        "recommended_ike": "ike=aes256gcm16-sha384-modp3072!",
        "recommended_esp": "esp=aes256gcm16-modp3072!",
        "compliance_tags": [TAG_NIST, TAG_PCIDSS],
    }
