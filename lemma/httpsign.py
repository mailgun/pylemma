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

import six
from cryptography.hazmat.primitives import constant_time
from expiringdict import ExpiringDict

# constants
_MAX_SKEW_SEC = 5 # 5 sec
_CACHE_TIMEOUT = 100  # 100 sec
_CACHE_CAPACITY = 5000 * _CACHE_TIMEOUT  # 5,000 msg/sec * 100 sec = 500,000 msg
_SIGNATURE_VERSION = "2"

# module level variables
_lock = threading.RLock()
_shared_key = None
_nonce_cache = None


def initialize(keypath, cache_capacity=_CACHE_CAPACITY,
               cache_timeout=_CACHE_TIMEOUT):
    """
    Initializes module by loading a shared key as well as nonce cache.

    This module can handle authenticating 5,000 requests/second, if you need to
    authenticate more requests than that, set the cache capacity and timeout
    accordingly.
    """
    try:
        shared_key = open(keypath).read().strip('\n')
    except IOError:
        shared_key = None

    initialize_with_key(shared_key, cache_capacity, cache_timeout)


def initialize_with_key(shared_key, cache_capacity=_CACHE_CAPACITY,
                        cache_timeout=_CACHE_TIMEOUT):
    """
    Initializes module with the specified shared key as well as nonce cache.

    This module can handle authenticating 5,000 requests/second, if you need to
    authenticate more requests than that, set the cache capacity and timeout
    accordingly.
    """

    global _shared_key
    _shared_key = shared_key

    global _nonce_cache
    _nonce_cache = ExpiringDict(max_len=cache_capacity,
                                max_age_seconds=cache_timeout)


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
    if not _shared_key:
        if not key:
            raise AuthenticationException('No shared secret provided.')
    if _nonce_cache is None:
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
        shared_secret = _shared_key

    # get hmac over timestamp, nonce, and request body
    signature = _compute_mac(shared_secret, timestamp, nonce, request_body,
        http_verb=http_verb, http_resource_uri=http_resource_uri, headers=headers)

    return timestamp, nonce, signature.decode("utf-8"), _SIGNATURE_VERSION


def authenticate_request(timestamp, nonce, request_body, signature, signature_version="2",
    http_verb=None, http_resource_uri=None, headers=None, key=None, metrics_prefix=None):
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

    Raises an AuthenticationException.
    """

    # if shared secret is not loaded, don't authenticate anything
    if not _shared_key:
        if not key:
            raise AuthenticationException('No shared secret provided.')

    # if nonce cache not loaded, don't authenticate anything
    if _nonce_cache is None:
        raise AuthenticationException('Nonce cache not configured.')

    # if any parameters are missing, return false
    if not timestamp or not nonce or not signature:
        raise AuthenticationException('Missing parameters.')

    # make request body an empty string if it doesn't exist (GET request).
    if not request_body:
        request_body = ''

    # if we are passed in a key use it, otherwise use the global SHARED_SECRET
    if key:
        shared_secret = key
    else:
        shared_secret = _shared_key

    # check the hmac, will raise AuthenticationException on failure
    _check_mac(shared_secret, timestamp, nonce, request_body, signature,
        http_verb=http_verb, http_resource_uri=http_resource_uri, headers=headers)

    # check timestamp, will raise AuthenticationException on failure
    _check_timestamp(timestamp)

    # check to see if we have seen nonce before, will raise AuthenticationException on failure
    _nonce_in_cache(nonce)


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
    Checks if given timestamp is within a valid time range. Raises AuthenticationException.
    """

    now = int(time.time())
    timestamp = int(timestamp)

    # if timestamp is from the future, it's invalid
    if timestamp >= now + _MAX_SKEW_SEC:
        raise AuthenticationException(
            'timestamp header from the future; now: {}, timestamp: {}, diff: {}'.format(now, timestamp, timestamp-now))

    # if the timestamp is older than ttl - skew, it's invalid
    if timestamp <= now - (_CACHE_TIMEOUT - _MAX_SKEW_SEC):
        raise AuthenticationException(
            'timestamp header too old; now: {}, timestamp: {}, diff: {}'.format(now, timestamp, now-timestamp))


def _nonce_in_cache(nonce):
    """
    Checks if the nonce has been seen before. Raises AuthenticationException.
    """

    with _lock:
        # if nonce has been seen before, it's invalid, otherwise add to cache.
        if nonce in _nonce_cache:
            raise AuthenticationException('nonce already in cache: {}'.format(nonce))
        else:
            _nonce_cache[nonce] = True

        return

    raise AuthenticationException('Unable to obtain lock!')


def _compute_mac(shared_secret, timestamp, nonce, body,
    http_verb=None, http_resource_uri=None, headers=None):
    """
    Given a timestamp, nonce, body, and optionally headers, returns hmac of
    those values concatenated with each other along with the shared secret.

    >>> _compute_mac('1406847690', '919368ACF548EE2BF635B071657B0B6F', 'hi')
    50b828e3c9fdf849c5e6ee572604b00bc32663dce0c74fdf0f5b5d3261680efa
    """

    # required parameters (timestamp, nonce, and body)
    t = to_binary(timestamp)
    n = to_binary(nonce)
    b = to_binary(body)
    parts = [to_binary(len(t)), t,
             to_binary(len(n)), n,
             to_binary(len(b)), b]

    # optional parameters (http_verb, http_resource_uri)
    if http_verb and http_resource_uri:
        h = to_binary(http_verb)
        parts.append(to_binary(len(h)))
        parts.append(h)
        r = to_binary(http_resource_uri)
        parts.append(to_binary(len(r)))
        parts.append(r)

    # optional parameters (headers)
    if headers:
        for k, v in six.iteritems(headers):
            hv = to_binary(v)
            parts.append(to_binary(len(hv)))
            parts.append(hv)

    message = b'|'.join(parts)

    # return hmac-sha256 hex digest of the hmac
    hasher = hmac.new(
        key=to_binary(shared_secret),
        msg=message,
        digestmod=hashlib.sha256)
    return to_binary(hasher.hexdigest())


def _check_mac(shared_secret, timestamp, nonce, body, message_hmac,
               http_verb=None, http_resource_uri=None, headers=None):
    """
    Computes HMAC and compares expected and obtained values. Performs constant
    time comparison. Raises AuthenticationException.
    """

    # compute the expected hmac
    expected_hmac = _compute_mac(shared_secret, timestamp, nonce, body,
                                 http_verb=http_verb,
                                 http_resource_uri=http_resource_uri,
                                 headers=headers)

    # constant time check of expected againstreceived hmac
    if not constant_time.bytes_eq(to_binary(message_hmac), expected_hmac):
        raise AuthenticationException('signature header value does not match computed value')


def to_binary(o):
    """
    Safely returns a UTF-8 encoded bytes of a given object

    >>> utils.to_binary('hi')
    b'hi'
    """
    if isinstance(o, six.binary_type):
        return o
    if isinstance(o, six.text_type):
        return o.encode("utf-8", "ignore")
    return to_binary(str(o))


class AuthenticationException(Exception):
    """
    Raised whenever some errors occurs while authenticating a request.
    """

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)
