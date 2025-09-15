"""micropython library for aws sigv4 signing."""

import hashlib
import hmac
import time
import binascii


def _utc_timestamps():
    """utc timestamp generation.

    returns: (amzdate, datestamp) - iso8601 timestamp and yyyymmdd date
    """
    t = time.gmtime()
    amzdate = "%04d%02d%02dT%02d%02d%02dZ" % t[:6]
    datestamp = amzdate[:8]
    return amzdate, datestamp


def _sha256_hex(data):
    """hex-encoded sha256 hash of data bytes."""
    return str(binascii.hexlify(hashlib.sha256(data).digest()), "utf-8")


def _sign(key, msg):
    """hmac-sha256 signature of msg using key."""
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _sig_key(secret, datestamp, region, service):
    """derives aws4 signing key from secret + context.

    implements the aws4 key derivation chain:
    kSecret -> kDate -> kRegion -> kService -> kSigning
    """
    k = ("AWS4" + secret).encode()
    k = _sign(k, datestamp)
    k = _sign(k, region)
    k = _sign(k, service)
    return _sign(k, "aws4_request")


def _canonical_request(method, host, path, body):
    """canonical request string per aws sigv4 spec.

    minimal implementation - no query params or extra headers supported.
    """
    # only host header + sha256 of body
    payload_hash = _sha256_hex(body)
    return "\n".join(
        (
            method,
            path,
            "",  # querystring (empty)
            "host:%s" % host,
            "",
            "host",
            payload_hash,
        )
    )


def _string_to_sign(amzdate, datestamp, region, service, creq):
    """builds the string-to-sign for sigv4.

    returns: (string_to_sign, credential_scope)
    """
    scope = "%s/%s/%s/aws4_request" % (datestamp, region, service)
    return (
        "AWS4-HMAC-SHA256\n%s\n%s\n%s"
        % (amzdate, scope, _sha256_hex(creq.encode()))
    ), scope


def _auth_header(ak, scope, sig):
    """formats the authorization header value."""
    return (
        "AWS4-HMAC-SHA256 "
        "Credential=%s/%s, SignedHeaders=host, Signature=%s" % (ak, scope, sig)
    )


def sign_request_headers(
    method, host, path, body, ak, sk, region, service, session_token=None
):
    """generates aws sigv4 signed headers for http requests.

    minimal sigv4 implementation - signs only host header + body hash.
    assumes json content-type.

    args:
        method: http method (GET, POST, etc)
        host: hostname (will be lowercased)
        path: request path
        body: request body as bytes
        ak: aws access key id
        sk: aws secret access key
        region: aws region
        service: aws service name
        session_token: optional session token for temp creds

    returns:
        dict of http headers ready for requests
    """
    host = host.lower()
    amzdate, datestamp = _utc_timestamps()
    creq = _canonical_request(method, host, path, body)
    sts, scope = _string_to_sign(amzdate, datestamp, region, service, creq)
    key = _sig_key(sk, datestamp, region, service)
    sig = hmac.new(key, sts.encode(), hashlib.sha256).hexdigest()
    headers = {
        "Authorization": _auth_header(ak, scope, sig),
        "x-amz-date": amzdate,
        "Host": host,
        "Content-Type": "application/json",
    }
    if session_token:
        headers["x-amz-security-token"] = session_token

    return headers
