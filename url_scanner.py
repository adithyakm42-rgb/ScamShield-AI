
"""URL screening using local rules and Google Safe Browsing."""
import ipaddress
import os
import re
from urllib.parse import urlparse

import requests

SUSPICIOUS_WORDS = {
    "verify", "login", "password", "account", "update", "payment",
    "wallet", "claim", "urgent", "otp", "kyc", "secure"
}

GAMBLING_WORDS = {
    "aviator", "bet", "betting", "casino", "gambling", "slot",
    "slots", "rummy", "teenpatti", "poker", "stake", "sportsbook"
}

SHORTENED_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly",
    "shorturl.at", "ow.ly", "rb.gy", "buff.ly", "rebrand.ly"
}

TRACKING_KEYS = {
    "click_id", "gclid", "fbclid", "utm_source", "utm_campaign",
    "sub_id1", "sub_id2", "sub_id3", "of_id"
}

SAFE_BROWSING_ENDPOINT = (
    "https://safebrowsing.googleapis.com/v5/urls:search"
)


def _score_level(score):
    if score >= 60:
        return "High"
    if score >= 30:
        return "Medium"
    return "Low"


def _google_safe_browsing_check(url):
    """Return Google threat matches, or an unavailable status."""
    api_key = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY")

    if not api_key:
        return {
            "status": "not_configured",
            "threat_types": [],
            "message": "Google Safe Browsing API key is not configured."
        }

    try:
        response = requests.get(
            SAFE_BROWSING_ENDPOINT,
            params=[
                ("key", api_key),
                ("urls", url)
            ],
            timeout=8
        )

        if response.status_code != 200:
            return {
                "status": "unavailable",
                "threat_types": [],
                "message": f"Google API returned HTTP {response.status_code}."
            }

        data = response.json()
        threats = data.get("threats", [])

        threat_types = sorted({
            threat_type
            for threat in threats
            for threat_type in threat.get("threatTypes", [])
        })

        if threat_types:
            return {
                "status": "known_threat",
                "threat_types": threat_types,
                "message": "Google Safe Browsing matched this URL against a known threat."
            }

        return {
            "status": "no_match",
            "threat_types": [],
            "message": "No match found in the Google Safe Browsing threat lists."
        }

    except requests.RequestException:
        return {
            "status": "unavailable",
            "threat_types": [],
            "message": "Google Safe Browsing could not be reached."
        }
    except (ValueError, KeyError, TypeError):
        return {
            "status": "unavailable",
            "threat_types": [],
            "message": "Google Safe Browsing returned an unexpected response."
        }


def analyze_url(raw_url):
    """Analyze a URL using local rules and an optional live threat check."""
    raw_url = (raw_url or "").strip()

    reasons = []
    informational = []
    score = 0

    if not raw_url:
        return {
            "prediction": "Invalid URL",
            "risk_score": 0,
            "reasons": ["Please enter a website URL."],
            "informational": [],
            "risk_level": "Unknown",
            "review_required": True,
            "normalized_url": "",
            "domain": "",
            "threat_status": "not_checked",
            "threat_types": [],
            "live_check": "not_checked"
        }

    candidate = raw_url if "://" in raw_url else "https://" + raw_url

    try:
        parsed = urlparse(candidate)
        hostname = parsed.hostname

        if parsed.scheme.lower() not in {"http", "https"}:
            raise ValueError("Unsupported URL scheme")

        if not hostname or "." not in hostname:
            raise ValueError("Missing or incomplete hostname")

        port = parsed.port

    except (ValueError, UnicodeError):
        return {
            "prediction": "Invalid or unsupported URL",
            "risk_score": 0,
            "reasons": [
                "The URL format is invalid or uses an unsupported scheme."
            ],
            "informational": [],
            "risk_level": "Unknown",
            "review_required": True,
            "normalized_url": candidate,
            "domain": "",
            "threat_status": "not_checked",
            "threat_types": [],
            "live_check": "not_checked"
        }

    host = hostname.lower().rstrip(".")
    normalized_url = candidate
    lower_all = (raw_url + " " + host).lower()

    def add(message, points):
        nonlocal score
        reasons.append(message)
        score += points

    if parsed.scheme.lower() != "https":
        add("The link uses HTTP instead of HTTPS.", 15)

    if parsed.username is not None or parsed.password is not None:
        add("The address contains embedded credentials.", 30)

    if "@" in parsed.netloc:
        add("The address contains an @ symbol that may disguise its destination.", 20)

    try:
        ipaddress.ip_address(host)
        add("The website uses a raw IP address instead of a domain name.", 25)
    except ValueError:
        pass

    if host in SHORTENED_DOMAINS:
        add("A URL-shortening service hides the final destination.", 20)

    if any(label.startswith("xn--") for label in host.split(".")):
        add("The domain contains an internationalized/punycode label.", 20)

    if port is not None and port not in {80, 443}:
        add("The link uses a non-standard web port.", 15)

    if len(raw_url) > 180:
        add("The URL is unusually long.", 10)

    found_gambling = sorted(
        word for word in GAMBLING_WORDS
        if re.search(
            rf"(?<![a-z0-9]){re.escape(word)}(?![a-z0-9])",
            lower_all
        )
    )

    if found_gambling:
        add(
            "The URL contains gambling or betting-related wording: "
            + ", ".join(found_gambling) + ".",
            20
        )
        informational.append(
            "Gambling wording identifies a category, not proof of fraud."
        )

    found_sensitive = sorted(
        word for word in SUSPICIOUS_WORDS
        if re.search(
            rf"(?<![a-z0-9]){re.escape(word)}(?![a-z0-9])",
            lower_all
        )
    )

    if found_sensitive:
        add(
            "The URL contains sensitive-action wording: "
            + ", ".join(found_sensitive) + ".",
            10
        )

    if any(key in parsed.query.lower() for key in TRACKING_KEYS):
        informational.append(
            "Advertising and click-tracking parameters were found. "
            "These are not proof of fraud."
        )

    if len(host.split(".")) >= 5:
        add("The domain has an unusually deep subdomain structure.", 10)

    # Live threat-intelligence check
    live_result = _google_safe_browsing_check(normalized_url)
    threat_status = live_result["status"]
    threat_types = live_result["threat_types"]

    if threat_status == "known_threat":
        score = 100
        reasons.append(
            "KNOWN THREAT: Google Safe Browsing identified this URL "
            "as a reported threat."
        )
        reasons.extend(
            "Threat category: " + threat_type
            for threat_type in threat_types
        )

    elif threat_status == "no_match":
        informational.append(live_result["message"])

    else:
        informational.append(live_result["message"])

    score = min(score, 100)

    if threat_status == "known_threat":
        level = "High"
        prediction = "KNOWN THREAT - Reported Unsafe URL"

    elif score >= 60:
        level = "High"
        prediction = "HIGH RISK - Multiple Warning Indicators"

    elif score >= 30:
        level = "Medium"
        prediction = "MEDIUM RISK - Suspicious URL"

    elif reasons:
        level = "Low"
        prediction = "LOW SCORE - Manual Review Recommended"

    else:
        level = "Low"
        prediction = "No Major Warning Patterns - Not Verified Safe"

    if not reasons:
        informational.append(
            "No local warning patterns were found. "
            "This does not prove the website is safe."
        )

    return {
        "prediction": prediction,
        "risk_score": score,
        "reasons": reasons,
        "informational": informational,
        "risk_level": level,
        "review_required": (
            bool(reasons) or threat_status != "no_match"
        ),
        "normalized_url": normalized_url,
        "domain": host,
        "threat_status": threat_status,
        "threat_types": threat_types,
        "live_check": threat_status
    }
