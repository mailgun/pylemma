"""
Module auth provides tools for signing and authenticating HTTP requests between
web services. See docs/httpsign.rst for more details.
"""
import base64
import hashlib
import hmac
import os
import threading
import time

from cryptography.hazmat.primitives import constant_time
from expiringdict import ExpiringDict

# constants
MAX_SKEW_SEC = 5 # 5 sec
CACHE_TIMEOUT = 100  # 30 sec
CACHE_CAPACITY = 5000 * CACHE_TIMEOUT  # 5,000 msg/sec * 100 sec = 500,000 msg
SIGNATURE_VERSION = "2"

# module level variables
LOCK = threading.RLock()
SHARED_SECRET = None
NONCE_CACHE = None


def initialize(keypath, cache_capacity=CACHE_CAPACITY,
               cache_timeout=CACHE_TIMEOUT):
    """
    Initializes module by loading a shared key as well as nonce cache. This
    module can handle authenticating 5,000 requests/second, if you need to
    authenticate more requests than that, set the cache capacity and timeout
    accordingly.
    """

    global SHARED_SECRET, NONCE_CACHE

    # load shared secret from disk
    try:
        SHARED_SECRET = open(keypath).read().strip('\n')
    except IOError, ioe:
        SHARED_SECRET = None

    # configure nonce cache
    NONCE_CACHE = ExpiringDict(
        max_len=cache_capacity, max_age_seconds=cache_timeout)


def sign_request(request_body,
    http_verb=None, http_resource_uri=None, headers=None, key=None):
    """
    Given a request body, signs request using an HMAC. Optional parameters are:

    1. http_verb and http_resource_uri. http_verb is an HTTP verb and
       http_resource_uri is the URI of the HTTP request. For example, if you are
       performing a GET request on http://www.example.com/path?key=value#fragment
       then http_verb would be "GET" and http_resource_uri would be
       "/path?key=value#fragment".
    2. headers. headers is a dictonary of headers to also sign along with the
       request. For example, the dictonary may look like:
       {"X-Mailgun-Custom-Header": "foobar"}
    3. key. key is provided if you wish to override the key this module was
       initialized with and sign with a different key.

    Returns tuple of timestamp, nonce, message signature, and signature version.

    >>> sign_request('{"hello": "world"}')
    ('...', '...', '...', '...')
    >>> sign_request('{"hello": "world"}', headers={"X-Custom-Header": "foo"})
    ('...', '...', '...', '...')
    >>> sign_request('{"hello": "world"}', http_verb="GET", http_resource_uri="/path")
    ('...', '...', '...', '...')
    """

    # if shared secret or nonce cache not loaded, don't sign anything
    if not SHARED_SECRET:
        if not key:
            raise AuthenticationException('No shared secret provided.')
    if NONCE_CACHE is None:
        raise AuthenticationException('Nonce cache not configured.')

    # make request body an empty string if it doesn't exist (GET request).
    if not request_body:
        request_body = ''

    # get 128-bit random number from /dev/urandom and base16 encode it
    nonce = _generate_nonce(128)

    # get current timestamp
    timestamp = _get_timestamp()

    # if we are passed in a key use it, otherwise use the global SHARED_SECRET
    if key:
        shared_secret = key
    else:
        shared_secret = SHARED_SECRET

    # get hmac over timestamp, nonce, and request body
    signature = _compute_mac(shared_secret, timestamp, nonce, request_body,
        http_verb=http_verb, http_resource_uri=http_resource_uri, headers=headers)

    return timestamp, nonce, signature, SIGNATURE_VERSION


def authenticate_request(timestamp, nonce, request_body, signature,
    signature_version="2", http_verb=None, http_resource_uri=None, headers=None, key=None):
    """
    Given a timestamp, nonce, request body, signature, and optionally (signature_version,
    http_verb and http_resource_uri, headers, and key:

    1. Computes HMAC to ensure it matches given HMAC.
    2. Checks the timestamp to see if its within allowable timewindow.
    3. Check if the nonce has been seen in the cache before.

    If any of the optional parameters are passed in, they are used computing the
    signature of the request.

    If a key is passed in, that key is used instead of the one the module was
    initialized with.

    Returns a boolean.
    """

    # if shared secret or nonce cache not loaded, don't authenticate anything
    if not SHARED_SECRET:
        if not key:
            raise AuthenticationException('No shared secret provided.')
    if NONCE_CACHE is None:
        raise AuthenticationException('Nonce cache not configured.')

    # if any parameters are missing, return false
    if not timestamp or not nonce or not signature:
        return False

    # make request body an empty string if it doesn't exist (GET request).
    if not request_body:
        request_body = ''

    # if we are passed in a key use it, otherwise use the global SHARED_SECRET
    if key:
        shared_secret = key
    else:
        shared_secret = SHARED_SECRET

    # check the hmac
    if not _check_mac(shared_secret, timestamp, nonce, request_body, signature,
            http_verb=http_verb, http_resource_uri=http_resource_uri, headers=headers):
        return False

    # check timestamp
    if not _check_timestamp(timestamp):
        return False

    # check to see if we have seen nonce before
    if _nonce_in_cache(nonce):
        return False

    # all checks pass, valid request
    return True


def _generate_nonce(n):
    """
    Uses operating system source of randomness to generate an n-bit integer
    to use as nonce value. Returns a hex-encoded version of the random number.

    >>> _generate_nonce()
    919368ACF548EE2BF635B071657B0B6F
    """

    return base64.b16encode(os.urandom(n/8))


def _get_timestamp():
    """
    Returns a Unix timestamp string which denotes the number of seconds that
    have elapsed since January 1, 1970 in UTC.

    >>> _get_timestamp()
    1406847690
    """

    return int(time.time())


def _check_timestamp(timestamp):
    """
    Checks if given timestamp is within a valid time range. Returns a boolean.
    """

    now = int(time.time())
    timestamp = int(timestamp)

    # if timestamp is from the future, it's invalid
    if timestamp >= now + MAX_SKEW_SEC:
        return False

    # if the timestamp is older than ttl - skew, it's invalid
    if timestamp <= now - (CACHE_TIMEOUT - MAX_SKEW_SEC):
        return False

    return True


def _nonce_in_cache(nonce):
    """
    Checks if the nonce has been seen before. Returns a boolean.
    """

    with LOCK:
        # if nonce has been seen before, it's invalid, otherwise add to cache.
        if nonce in NONCE_CACHE:
            return True
        else:
            NONCE_CACHE[nonce] = True

        return False

    raise AuthenticationException('Unable to obtain lock!')


def _compute_mac(shared_secret, timestamp, nonce, body,
    http_verb=None, http_resource_uri=None, headers=None):
    """
    Given a timestamp, nonce, body, and optionally headers, returns hmac of
    those values concatenated with each other along with the shared secret.

    >>> _compute_mac('1406847690', '919368ACF548EE2BF635B071657B0B6F', 'hi')
    50b828e3c9fdf849c5e6ee572604b00bc32663dce0c74fdf0f5b5d3261680efa
    """

    # convert all to utf-8
    t = to_utf8(timestamp)
    n = to_utf8(nonce)
    b = to_utf8(body)
    h = to_utf8(http_verb)
    r = to_utf8(http_resource_uri)

    # requred parameters (timestamp, nonce, and body)
    message = '{0}|{1}|{2}|{3}|{4}|{5}'.format(len(t), t, len(n), n, len(b), b)

    # optional parameters (http_verb, http_resource_uri)
    if http_verb and http_resource_uri:
        part = '|{0}|{1}|{2}|{3}'.format(len(h), h, len(r), r)
        message = ''.join([message, part])

    # optional parameters (headers)
    if headers:
        parts = []
        for k, v in headers.iteritems():
            # convert to utf-8, then build string
            hv = to_utf8(v)
            parts.append('|{0}|{1}'.format(len(hv), hv))
        message = ''.join([message] + parts)

    # return hmac-sha256 hex digest of the hmac
    return hmac.new(
        key=shared_secret,
        msg=message,
        digestmod=hashlib.sha256).hexdigest()


def _check_mac(shared_secret, timestamp, nonce, body, message_hmac,
    http_verb=None, http_resource_uri=None, headers=None):
    """
    Computes HMAC and compares expected and obtained values. Performs constant
    time comparison. Returns a boolean.
    """

    # compute the expected hmac
    expected_hmac = _compute_mac(shared_secret, timestamp, nonce, body,
        http_verb=http_verb, http_resource_uri=http_resource_uri, headers=headers)

    # constant time check of expected againstreceived hmac
    return constant_time.bytes_eq(to_utf8(message_hmac), expected_hmac)


def to_utf8(str_or_unicode):
    """
    Safely returns a UTF-8 version of a given string

    >>> utils.to_utf8(u'hi')
    'hi'
    """

    if isinstance(str_or_unicode, unicode):
        return str_or_unicode.encode("utf-8", "ignore")
    return str(str_or_unicode)


class AuthenticationException(Exception):
    """
    Raised whenever some errors occurs while authenticating a request.
    """

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)
