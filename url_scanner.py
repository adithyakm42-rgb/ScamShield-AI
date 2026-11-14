
"""URL screening using local rules and Google Safe Browsing."""

import ipaddress
import os
import re
from urllib.parse import urlparse

import requests


SUSPICIOUS_WORDS = {
    "verify", "login", "password", "account", "update",
    "payment", "wallet", "claim", "urgent", "otp",
    "kyc", "secure", "bank", "confirm", "security"
}

GAMBLING_WORDS = {
    "aviator", "bet", "betting", "casino", "gambling",
    "slot", "slots", "rummy", "teenpatti", "poker",
    "stake", "sportsbook"
}

SHORTENED_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly",
    "shorturl.at", "ow.ly", "rb.gy", "buff.ly", "rebrand.ly"
}

TRACKING_KEYS = {
    "click_id", "gclid", "fbclid", "utm_source",
    "utm_campaign", "sub_id1", "sub_id2", "sub_id3", "of_id"
}

SAFE_BROWSING_ENDPOINT = (
    "https://safebrowsing.googleapis.com/v4/threatMatches:find"
)

HOST_BAIT_WORDS = {
    "secure", "security", "bank", "account", "verify",
    "payment", "wallet", "login", "support", "confirm"
}

ACTION_WORDS = {
    "login", "verify", "confirm", "update",
    "claim", "otp", "password", "kyc"
}

FINANCIAL_WORDS = {
    "bank", "payment", "wallet", "account", "kyc", "otp"
}


def _score_level(score):
    if score >= 60:
        return "High"
    if score >= 30:
        return "Medium"
    return "Low"


def _google_safe_browsing_check(url):
    """Check a URL against Google's Safe Browsing threat lists."""

    api_key = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY")

    if not api_key:
        return {
            "status": "not_configured",
            "threat_types": [],
            "message": "Google Safe Browsing API key is not configured."
        }

    request_body = {
        "client": {
            "clientId": "ScamShieldAI",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = requests.post(
            SAFE_BROWSING_ENDPOINT,
            params={"key": api_key},
            json=request_body,
            timeout=8
        )

        if response.status_code != 200:
            return {
                "status": "unavailable",
                "threat_types": [],
                "message": (
                    "Google Safe Browsing returned HTTP "
                    + str(response.status_code) + "."
                )
            }

        data = response.json()
        matches = data.get("matches", [])

        threat_types = sorted({
            match.get("threatType", "UNKNOWN")
            for match in matches
        })

        if threat_types:
            return {
                "status": "known_threat",
                "threat_types": threat_types,
                "message": (
                    "Google Safe Browsing matched this URL "
                    "against a known threat list."
                )
            }

        return {
            "status": "no_match",
            "threat_types": [],
            "message": (
                "No match found in Google Safe Browsing. "
                "This does not prove the URL is safe."
            )
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
    """Analyze a URL using local rules and optional live threat checking."""

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

    candidate = (
        raw_url if "://" in raw_url
        else "https://" + raw_url
    )

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

    host_labels = set(re.findall(r"[a-z0-9]+", host))
    path_text = (parsed.path + " " + parsed.query).lower()

    def add(message, points):
        nonlocal score
        reasons.append(message)
        score += points

    # 1. Connection security
    if parsed.scheme.lower() != "https":
        add("The link uses HTTP instead of HTTPS.", 15)

    # 2. Embedded credentials
    if parsed.username is not None or parsed.password is not None:
        add("The address contains embedded credentials.", 30)

    if "@" in parsed.netloc:
        add(
            "The address contains an @ symbol that may disguise its destination.",
            20
        )

    # 3. Raw IP address
    try:
        ipaddress.ip_address(host)
        add(
            "The website uses a raw IP address instead of a domain name.",
            25
        )
    except ValueError:
        pass

    # 4. URL shortener
    if host in SHORTENED_DOMAINS:
        add("A URL-shortening service hides the final destination.", 20)

    # 5. Punycode domain
    if any(label.startswith("xn--") for label in host.split(".")):
        add("The domain contains an internationalized/punycode label.", 20)

    # 6. Non-standard port
    if port is not None and port not in {80, 443}:
        add("The link uses a non-standard web port.", 15)

    # 7. Long URL
    if len(raw_url) > 180:
        add("The URL is unusually long.", 10)

    # 8. Gambling category
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
            "Gambling wording identifies a category and is not evidence "
            "of fraud by itself."
        )

    # 9. Sensitive-action wording
    found_sensitive = sorted(
        word for word in SUSPICIOUS_WORDS
        if re.search(
            rf"(?<![a-z0-9]){re.escape(word)}(?![a-z0-9])",
            lower_all
        )
    )

    if len(found_sensitive) == 1:
        add(
            "The URL contains sensitive-action wording: "
            + ", ".join(found_sensitive) + ".",
            5
        )

    elif len(found_sensitive) == 2:
        add(
            "The URL combines sensitive-action wording: "
            + ", ".join(found_sensitive) + ".",
            12
        )

    elif len(found_sensitive) >= 3:
        add(
            "The URL contains several sensitive-action terms: "
            + ", ".join(found_sensitive) + ".",
            18
        )

    # 10. Multiple security-related hostname terms
    host_bait_found = sorted(
        HOST_BAIT_WORDS.intersection(host_labels)
    )

    if len(host_bait_found) >= 2:
        add(
            "The hostname combines multiple account/security-related "
            "terms: " + ", ".join(host_bait_found) + ".",
            20
        )

    # 11. Financial and action wording combination
    financial_found = FINANCIAL_WORDS.intersection(host_labels)

    action_found = ACTION_WORDS.intersection(
        set(re.findall(r"[a-z0-9]+", path_text)) | host_labels
    )

    if financial_found and action_found:
        add(
            "The URL combines financial/account wording with "
            "login, verification or other action wording.",
            15
        )

    # 12. Tracking parameters
    if any(key in parsed.query.lower() for key in TRACKING_KEYS):
        informational.append(
            "Advertising and click-tracking parameters were found. "
            "These are not proof of fraud."
        )

    # 13. Deep subdomains
    if len(host.split(".")) >= 5:
        add("The domain has an unusually deep subdomain structure.", 10)

    # 14. Reserved example domain
    if host.endswith(".example"):
        informational.append(
            "This uses the reserved .example domain suffix for testing. "
            "It is not evidence of a real phishing website."
        )

    # 15. Google Safe Browsing
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

    else:
        informational.append(live_result["message"])

    score = min(score, 100)

    # 16. Final risk classification
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
