"""Client-side vector sections: webhooks, relayUrls, blockedAddresses, relayErrors, directReceive.

Expectations are written out by hand from 08-relay.md (§ Webhooks, § Direct Delivery,
§ Client Rules); only the webhook HMACs are computed. Imported by generate-vectors.py.
"""

from __future__ import annotations

import hashlib
import hmac
import json

MAX_ENVELOPE_BYTES = 131072
MAX_DIRECT_BODY_BYTES = MAX_ENVELOPE_BYTES + 1024
TIMESTAMP_WINDOW_SECONDS = 300


def _j(o) -> str:
    return json.dumps(o, separators=(",", ":"))


# =====================================================================================
# webhooks (08 § Webhooks, Notification)
# =====================================================================================

WEBHOOK_SECRET = "whsec-0123456789abcdef"
WEBHOOK_TS = 1741000000
WEBHOOK_ACE_ID = "ace:sha256:" + "a" * 64
WEBHOOK_STREAM_ID = "1741000000000-0"
WEBHOOK_BODY = _j({"event": "message", "aceId": WEBHOOK_ACE_ID, "streamId": WEBHOOK_STREAM_ID})


def webhook_signature(secret: str, timestamp: int, body: str) -> str:
    mac = hmac.new(secret.encode(), f"{timestamp}.".encode() + body.encode(), hashlib.sha256)
    return "sha256=" + mac.hexdigest()


def _webhooks() -> dict:
    sig = webhook_signature(WEBHOOK_SECRET, WEBHOOK_TS, WEBHOOK_BODY)
    ok = {"aceId": WEBHOOK_ACE_ID, "streamId": WEBHOOK_STREAM_ID}
    cases: list[dict] = []

    def case(name, *, secret=WEBHOOK_SECRET, timestamp=str(WEBHOOK_TS), signature=sig, body=WEBHOOK_BODY,
             now=WEBHOOK_TS, result=None, error=None):
        entry = {"name": name, "secret": secret, "timestamp": timestamp, "signature": signature, "body": body, "now": now}
        if error is None:
            entry["result"] = result
        else:
            entry["error"] = error
        cases.append(entry)

    case("valid", result=ok)
    case("valid at now - window", now=WEBHOOK_TS + TIMESTAMP_WINDOW_SECONDS, result=ok)
    case("valid at now + window", now=WEBHOOK_TS - TIMESTAMP_WINDOW_SECONDS, result=ok)
    extra = _j({"event": "message", "aceId": WEBHOOK_ACE_ID, "streamId": WEBHOOK_STREAM_ID, "extra": 1})
    case("unknown body member ignored", body=extra, signature=webhook_signature(WEBHOOK_SECRET, WEBHOOK_TS, extra), result=ok)
    case("stale timestamp", now=WEBHOOK_TS + TIMESTAMP_WINDOW_SECONDS + 1, error="stale_timestamp")
    case("future timestamp", now=WEBHOOK_TS - TIMESTAMP_WINDOW_SECONDS - 1, error="stale_timestamp")
    case("wrong secret", secret=WEBHOOK_SECRET + "x", error="invalid_signature")
    case("tampered body", body=WEBHOOK_BODY.replace(WEBHOOK_STREAM_ID, "1741000000000-1"), error="invalid_signature")
    case("signature over a different timestamp", signature=webhook_signature(WEBHOOK_SECRET, WEBHOOK_TS + 1, WEBHOOK_BODY),
         error="invalid_signature")
    case("malformed signature: uppercase hex", signature="sha256=" + sig[7:].upper(), error="invalid_signature")
    case("malformed signature: no prefix", signature=sig[7:], error="invalid_signature")
    case("malformed signature: sha1 prefix", signature="sha1=" + sig[7:], error="invalid_signature")
    case("malformed signature: 63 hex digits", signature=sig[:-1], error="invalid_signature")
    case("malformed signature: empty", signature="", error="invalid_signature")
    case("malformed timestamp: leading zero", timestamp="0" + str(WEBHOOK_TS), error="invalid_argument")
    case("malformed timestamp: decimal point", timestamp=f"{WEBHOOK_TS}.0", error="invalid_argument")
    case("malformed timestamp: empty", timestamp="", error="invalid_argument")
    case("malformed timestamp: above 2^53-1", timestamp=str(2**53), error="invalid_argument")
    wrong_event = _j({"event": "ping", "aceId": WEBHOOK_ACE_ID, "streamId": WEBHOOK_STREAM_ID})
    case("authentic body with wrong event", body=wrong_event,
         signature=webhook_signature(WEBHOOK_SECRET, WEBHOOK_TS, wrong_event), error="invalid_argument")
    bad_stream = _j({"event": "message", "aceId": WEBHOOK_ACE_ID, "streamId": "latest"})
    case("authentic body with malformed streamId", body=bad_stream,
         signature=webhook_signature(WEBHOOK_SECRET, WEBHOOK_TS, bad_stream), error="invalid_argument")
    case("authentic body that is not JSON", body="not json",
         signature=webhook_signature(WEBHOOK_SECRET, WEBHOOK_TS, "not json"), error="invalid_argument")
    return {
        "rules": (
            "verifyWebhookNotification(secret, timestamp header, signature header, raw body as UTF-8 bytes) "
            "with the clock fixed at 'now' and the default window (TIMESTAMP_WINDOW_SECONDS). Check order: "
            "timestamp format (invalid_argument), signature format (invalid_signature), freshness "
            "(stale_timestamp), HMAC (invalid_signature), body shape (invalid_argument). 'result' is the "
            "returned {aceId, streamId}; 'error' is the ACEError code. A relay-side signer is checked against "
            "the 'result' cases: signWebhookNotification(secret, timestamp, body) == signature."
        ),
        "cases": cases,
    }


# =====================================================================================
# relayUrls (08 § Client Rules, Relay URL)
# =====================================================================================

RELAY_URLS = [
    ("https://relay.aceprotocol.org", "https://relay.aceprotocol.org"),
    ("https://relay.aceprotocol.org/", "https://relay.aceprotocol.org"),
    ("https://relay.aceprotocol.org//", "https://relay.aceprotocol.org"),
    ("HTTPS://Relay.AceProtocol.ORG/", "https://relay.aceprotocol.org"),
    ("https://relay.aceprotocol.org:443/", "https://relay.aceprotocol.org"),
    ("http://relay.example.com:80", "http://relay.example.com"),
    ("https://relay.example.com:80", "https://relay.example.com:80"),
    ("http://relay.example.com:443/", "http://relay.example.com:443"),
    ("https://relay.example.com:8443/", "https://relay.example.com:8443"),
    ("https://relay.example.com/ace/", "https://relay.example.com/ace"),
    ("https://relay.example.com/Ace/V1", "https://relay.example.com/Ace/V1"),
    ("http://127.0.0.1:3000/", "http://127.0.0.1:3000"),
    ("http://[::1]:3000/", "http://[::1]:3000"),
    ("ftp://relay.example.com", None),
    ("wss://relay.example.com", None),
    ("relay.example.com", None),
    ("", None),
    ("https://user@relay.example.com", None),
    ("https://user:pass@relay.example.com", None),
    ("https://relay.example.com?x=1", None),
    ("https://relay.example.com/?", None),
    ("https://relay.example.com/#", None),
    ("https://relay.example.com/#frag", None),
    ("https://relay.example.com:65536", None),
    (" https://relay.example.com", None),
    ("https://relay.example.com/ ", None),
    ("https://relay.example.com/a\tb", None),
    ("http://relay.example.com:80:80", None),
    ("https://relay.example.com:", None),
    ("https://relay.example.com:0", None),
    ("https://relay.example.com:0443", None),
    ("https://relay.example.com:000443", None),
    ("https://relay.example.com:123456", None),
    ("https://r\u00e9lay.example.com", None),
    ("https://relay%2Eexample.com", None),
    ("https://relay_1.example.com", None),
    ("https://xn--rlay-bpa.Example.com/", "https://xn--rlay-bpa.example.com"),
    ("http://[FE80::1]:8080/", "http://[fe80::1]:8080"),
    ("http://[::g]", None),
    ("http://[1.2.3.4]", None),
    ("http://[::1", None),
    ("http://[::1]x", None),
    ("http://[fe80::1%25en0]/", None),
]


def _relay_urls() -> dict:
    cases = []
    for url, norm in RELAY_URLS:
        cases.append({"input": url, "normalized": norm} if norm is not None else {"input": url, "error": "invalid_argument"})
    return {
        "rules": "normalizeRelayUrl(input) returns 'normalized', or throws ACEError 'error'.",
        "cases": cases,
    }


# =====================================================================================
# blockedAddresses (08 § Client Rules, Blocked Addresses)
# =====================================================================================

BLOCKED = [
    ("1.1.1.1", False), ("8.8.8.8", False), ("0.0.0.0", True), ("0.255.255.255", True),
    ("9.255.255.255", False), ("10.0.0.0", True), ("10.255.255.255", True), ("11.0.0.0", False),
    ("100.63.255.255", False), ("100.64.0.0", True), ("100.127.255.255", True), ("100.128.0.0", False),
    ("126.255.255.255", False), ("127.0.0.1", True), ("127.255.255.255", True), ("128.0.0.0", False),
    ("169.253.255.255", False), ("169.254.0.0", True), ("169.254.169.254", True), ("169.255.0.0", False),
    ("172.15.255.255", False), ("172.16.0.0", True), ("172.31.255.255", True), ("172.32.0.0", False),
    ("192.0.0.1", True), ("192.0.1.1", False), ("192.0.2.1", True), ("192.0.3.1", False),
    ("192.167.255.255", False), ("192.168.0.1", True), ("192.169.0.0", False),
    ("198.17.255.255", False), ("198.18.0.0", True), ("198.19.255.255", True), ("198.20.0.0", False),
    ("198.51.100.7", True), ("203.0.113.7", True), ("203.0.114.0", False),
    ("223.255.255.255", False), ("224.0.0.1", True), ("239.255.255.255", True), ("240.0.0.1", True),
    ("255.255.255.255", True),
    ("::", True), ("::1", True), ("2606:4700:4700::1111", False), ("2001:4860:4860::8888", False),
    ("100::1", True), ("100:0:0:1::1", False), ("2001:db8::1", True), ("2001:db9::1", False),
    ("fc00::1", True), ("fd12:3456::1", True), ("FD12:3456::1", True), ("fe80::1", True), ("febf::1", True),
    ("ff02::1", True),
    ("::ffff:127.0.0.1", True), ("::ffff:10.0.0.1", True), ("::ffff:a00:1", True), ("::ffff:8.8.8.8", False),
    ("::ffff:808:808", False), ("64:ff9b::7f00:1", True), ("64:ff9b::192.168.0.1", True), ("64:ff9b::808:808", False),
    # IPv4-embedding transition ranges are blocked whole, whatever the embedded IPv4.
    ("2002:7f00:1::1", True), ("2002:808:808::1", True), ("2003::1", False),  # 6to4 2002::/16
    ("2001:0:7f00:1::1", True), ("2001:0:4136:e378:8000:63bf:3fff:fdd2", True), ("2001:1::1", False),  # Teredo
    ("::7f00:1", True), ("::a00:1", True), ("::808:808", True), ("::8.8.8.8", True),  # IPv4-compatible ::/96
    ("64:ff9b:1:7f00:0:100::", True), ("64:ff9b:1:808:8:800::", True),  # local-use NAT64 64:ff9b:1::/48
    ("::ffff:0:a00:1", True), ("::ffff:0:808:808", True),  # SIIT ::ffff:0:0:0/96
    # Not an IP literal: blocked (fail closed).
    ("example.com", True), ("", True), ("1.2.3", True), ("1.2.3.4.5", True), ("256.0.0.1", True),
    (" 8.8.8.8", True), ("8.8.8.8/32", True), ("::g", True), ("[::1]", True), ("8.8.8.8%x", True),
    # An IPv6 zone (%zone) is ignored: judged by the address.
    ("fe80::1%en0", True), ("2606:4700:4700::1111%eth0", False),
]


def _blocked() -> dict:
    return {
        "rules": ("isBlockedAddress(address) returns 'blocked'. An IPv6 %zone suffix is ignored; any other input "
                  "that is not an IP literal is blocked (fail closed)."),
        "cases": [{"address": a, "blocked": b} for a, b in BLOCKED],
    }


# =====================================================================================
# relayErrors (08 § Client Rules, Responses)
# =====================================================================================


def _err(code: str, msg: str = "") -> str:
    return _j({"error": code, "message": msg} if msg else {"error": code})


RELAY_ERRORS = [
    # name, status, body, headers, code, relayCode, retryAfterSeconds
    ("301 redirect", 301, "", {"Location": "https://elsewhere.example.com/"}, "relay_protocol_error", None, None),
    ("302 redirect", 302, "", {"Location": "https://elsewhere.example.com/"}, "relay_protocol_error", None, None),
    ("307 redirect", 307, "", {"Location": "https://elsewhere.example.com/"}, "relay_protocol_error", None, None),
    ("308 redirect", 308, "", {"Location": "https://elsewhere.example.com/"}, "relay_protocol_error", None, None),
    ("303 redirect with Retry-After", 303, "", {"Location": "https://elsewhere.example.com/", "Retry-After": "5"},
     "relay_protocol_error", None, 5),
    ("204 where a JSON body was expected", 204, "", {}, "relay_protocol_error", None, None),
    ("200 where another status was expected", 200, _err("internal_error"), {}, "relay_protocol_error", "internal_error", None),
    ("400 invalid_argument", 400, _err("invalid_argument", "bad since"), {}, "relay_rejected", "invalid_argument", None),
    ("400 envelope_expired", 400, _err("envelope_expired"), {}, "envelope_expired", "envelope_expired", None),
    ("400 error member not a string", 400, _j({"error": 5}), {}, "relay_rejected", None, None),
    ("400 body not JSON", 400, "Bad Request", {}, "relay_rejected", None, None),
    ("400 with Retry-After", 400, _err("invalid_argument"), {"Retry-After": "5"}, "relay_rejected", "invalid_argument", None),
    ("401 invalid_signature", 401, _err("invalid_signature"), {}, "relay_rejected", "invalid_signature", None),
    ("403 not_registered", 403, _err("not_registered"), {}, "not_registered", "not_registered", None),
    ("403 other code", 403, _err("forbidden"), {}, "relay_rejected", "forbidden", None),
    ("404 unknown_peer", 404, _err("unknown_peer"), {}, "unknown_peer", "unknown_peer", None),
    ("404 without body", 404, "", {}, "relay_rejected", None, None),
    ("408 request timeout", 408, "", {}, "relay_unavailable", None, None),
    ("408 with Retry-After", 408, "", {"Retry-After": "3"}, "relay_unavailable", None, 3),
    ("409 replay after the retry", 409, _err("replay"), {}, "relay_rejected", "replay", None),
    ("409 identity_conflict", 409, _err("identity_conflict"), {}, "relay_rejected", "identity_conflict", None),
    ("409 envelope_expired (wrong status)", 409, _err("envelope_expired"), {}, "relay_rejected", "envelope_expired", None),
    ("413 payload too large", 413, _err("invalid_argument"), {}, "relay_rejected", "invalid_argument", None),
    ("418 unexpected 4xx", 418, "", {}, "relay_rejected", None, None),
    ("429 rate_limited", 429, _err("rate_limited"), {"Retry-After": "7"}, "relay_unavailable", "rate_limited", 7),
    ("429 rate_limited without Retry-After", 429, _err("rate_limited"), {}, "relay_unavailable", "rate_limited", None),
    ("429 without code", 429, "", {"Retry-After": "2"}, "relay_unavailable", None, 2),
    ("429 non-JSON body", 429, "Too Many Requests", {}, "relay_unavailable", None, None),
    ("429 recipient_inbox_full", 429, _err("recipient_inbox_full"), {"Retry-After": "7"}, "relay_rejected", "recipient_inbox_full", None),
    ("429 sender_quota_exceeded", 429, _err("sender_quota_exceeded"), {}, "relay_rejected", "sender_quota_exceeded", None),
    ("429 max_open_intents", 429, _err("max_open_intents"), {}, "relay_rejected", "max_open_intents", None),
    ("500 internal_error", 500, _err("internal_error"), {}, "relay_unavailable", "internal_error", None),
    ("502 HTML body", 502, "<html>Bad Gateway</html>", {}, "relay_unavailable", None, None),
    ("503 Retry-After seconds", 503, "", {"Retry-After": "120"}, "relay_unavailable", None, 120),
    ("503 Retry-After zero", 503, "", {"Retry-After": "0"}, "relay_unavailable", None, 0),
    ("503 Retry-After HTTP-date ignored", 503, "", {"Retry-After": "Wed, 21 Oct 2015 07:28:00 GMT"}, "relay_unavailable", None, None),
    ("503 Retry-After fraction ignored", 503, "", {"Retry-After": "1.5"}, "relay_unavailable", None, None),
    ("503 Retry-After negative ignored", 503, "", {"Retry-After": "-1"}, "relay_unavailable", None, None),
    ("504 gateway timeout", 504, "", {}, "relay_unavailable", None, None),
    ("599 last 5xx", 599, "", {}, "relay_unavailable", None, None),
    ("600 out-of-range status", 600, _err("internal_error"), {"Retry-After": "2"}, "relay_protocol_error", "internal_error", 2),
]

_TRANSIENT = {"relay_unavailable", "relay_protocol_error"}


def _relay_errors() -> dict:
    cases = []
    for name, status, body, headers, code, relay_code, retry in RELAY_ERRORS:
        cases.append({
            "name": name, "status": status, "headers": headers, "body": body,
            "code": code, "category": "transient" if code in _TRANSIENT else "permanent",
            "relayCode": relay_code, "retryAfterSeconds": retry,
        })
    return {
        "rules": (
            "Map one relay response that is not the call's expected success (status, headers, raw body; "
            "a 2xx here is one the call did not expect, e.g. 204 where a JSON body is expected) to an ACEError: 'code', its "
            "'category', the relay error code ('relayCode', null when absent) and 'retryAfterSeconds' "
            "(null when not attached). The error's HTTP status equals 'status'. Header names are "
            "case-insensitive. The single 409 replay retry is not part of the mapping."
        ),
        "cases": cases,
    }


# =====================================================================================
# directReceive (08 § Direct Delivery, Receiver): wrapper-level cases
# =====================================================================================

DIRECT = [
    # name, body (str) or ("hex", str), padTo, status, error
    ("empty body", "", None, 400, "invalid_argument"),
    ("not JSON", "{", None, 400, "invalid_argument"),
    ("message string with invalid UTF-8", ("hex", "7b226d657373616765223a22ff227d"), None, 400, "invalid_argument"),
    ("top-level array", "[]", None, 400, "invalid_argument"),
    ("top-level string", "\"message\"", None, 400, "invalid_argument"),
    ("top-level null", "null", None, 400, "invalid_argument"),
    ("object without message", _j({"msg": {}}), None, 400, "invalid_argument"),
    ("message null", _j({"message": None}), None, 400, "invalid_envelope"),
    ("message number", _j({"message": 5}), None, 400, "invalid_envelope"),
    ("message string", _j({"message": "x"}), None, 400, "invalid_envelope"),
    ("message array", _j({"message": []}), None, 400, "invalid_envelope"),
    ("message empty object", _j({"message": {}}), None, 400, "invalid_envelope"),
    ("message missing envelope fields", _j({"message": {"ace": "2.0"}}), None, 400, "invalid_envelope"),
    ("unknown request member ignored", _j({"message": {}, "extra": 1}), None, 400, "invalid_envelope"),
    ("body of exactly MAX_DIRECT_BODY_BYTES", _j({"message": 5}), MAX_DIRECT_BODY_BYTES, 400, "invalid_envelope"),
    ("body of MAX_DIRECT_BODY_BYTES + 1", _j({"message": 5}), MAX_DIRECT_BODY_BYTES + 1, 413, "payload_too_large"),
    ("non-JSON body of MAX_DIRECT_BODY_BYTES + 1", "x", MAX_DIRECT_BODY_BYTES + 1, 413, "payload_too_large"),
]


def _direct() -> dict:
    cases = []
    for name, body, pad, status, error in DIRECT:
        entry: dict = {"name": name}
        if isinstance(body, tuple):
            entry["bodyHex"] = body[1]
        else:
            entry["body"] = body
        if pad is not None:
            entry["padTo"] = pad
        entry["status"] = status
        entry["error"] = error
        cases.append(entry)
    return {
        "rules": (
            "Request bytes are UTF-8('body') or hex-decoded 'bodyHex', then right-padded with ASCII spaces "
            "(0x20) to 'padTo' bytes when given. Pass them to SecureMailbox.receiveDirect (receive_direct) of an open mailbox of any "
            "identity. The reply has HTTP status 'status' and body {ok: false, error: 'error'}."
        ),
        "maxDirectBodyBytes": MAX_DIRECT_BODY_BYTES,
        "cases": cases,
    }


def client_vectors() -> dict:
    return {
        "webhooks": _webhooks(),
        "relayUrls": _relay_urls(),
        "blockedAddresses": _blocked(),
        "relayErrors": _relay_errors(),
        "directReceive": _direct(),
    }
