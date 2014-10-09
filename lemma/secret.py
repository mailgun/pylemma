"""
Module secret can be used to encrypt/decrypt authenticated messages.
See docs/secret.rst for more details.
"""
import base64
import os
import __builtin__

import nacl.exceptions
import nacl.secret
import nacl.utils

import lemma.metrics

# constants
NONCE_LEN = 24 # length of nonce
SECRET_KEY_LEN = 32 # length of secret key

# module level variables
SECRET_KEY = None
BOX = None


def initialize(keypath=None):
    """
    Initializes module by loading a secret key into memory and setting up
    the secret box used to encrypt and decrypt with that key.

    If no keypath is passed in, the secret box will not be setup, and the
    key must be passed in each time the functions open or seal are called.
    The keypath passed must also be the path to hex-encoded key on disk.
    New lines will be stripped and not considered part of the key.
    """

    global SECRET_KEY, BOX

    # no key passed in
    if keypath is None:
        SECRET_KEY = None
        BOX = None
        return

    try:
        # load shared secret from disk
        SECRET_KEY = _read_key_from_disk(keypath)

    except IOError as ioe:
        # raise an exception if we had a problem loading the key

        SECRET_KEY = None
        BOX = None
        raise SecretException('Unable to read key from disk: {}'.format(ioe))

    # initialize the secret box with key bytes
    initialize_with_key(SECRET_KEY)


def initialize_with_key(keybytes=None):
    """
    Initializes module with given keybytes. Here the passed in key must be the
    key bytes themself and not the hex-encoded key.

    If no keybytes are passed in, the secret box will not be setup, and the key
    must be passed in each time the functions open or seal are called.
    """

    global SECRET_KEY, BOX

    # no key bytes passed in
    if keybytes is None:
        SECRET_KEY = None
        BOX = None
        return

    # setup the secret box
    SECRET_KEY = keybytes
    BOX = nacl.secret.SecretBox(SECRET_KEY)


def seal(plaintext, key=None, emit_metrics=True):
    """
    Given some plaintext, seal will encrypt and MAC the resulting ciphertext.
    The ciphertext and a nonce is returned on successful encryption.

    The nonce is not secret, but is required to decrypt the ciphertext.

    If a key is passed in, that key will be used to seal the plaintext. This
    key must be the key bytes, not the hex-encoded key. Use the hexkey_to_key
    function to convert a hex-encoded key into a key.

    >>> ciphertext, nonce = seal('hello, box!')
    >>> print bytes_to_hexstring(ciphertext)
    588362b116c2d90ccb909f201098c213369a5423a8e68272d444ae
    >>> print bytes_to_hexstring(nonce)
    000102030405060708090a0b0c0d0e0f1011121314151617
    """

    # generate nonce
    nonce = _generate_random_bytes(NONCE_LEN)

    # get a box, if key is passed in, use that to setup box
    box = _obtain_box(key)

    # seal the message inside the box
    encrypted_message = box.encrypt(plaintext, nonce)

    # return the sealed message, a dict with the ciphertext and nonce
    return encrypted_message.ciphertext, encrypted_message.nonce


def open(ciphertext, nonce, key=None, emit_metrics=True):
    """
    Given ciphertext and a nonce, open will authenticate that the ciphertext
    has not been tampered with and return the decrypted plaintext.

    If a key is passed in, that key will be used to seal the plaintext. This key
    must be the key bytes, not the hex-encoded key.

    >>> ciphertext = hexstring_to_bytes('588362b116c2d90ccb909f201098c213369a5423a8e68272d444ae')
    >>> nonce = hexstring_to_bytes('000102030405060708090a0b0c0d0e0f1011121314151617')
    >>> open(ciphertext, nonce)
    'hello, box!'
    """

    # get a box, if key is passed in, use that to setup box
    box = _obtain_box(key)

    # open the box and retrieve the message
    try:
        plaintext = box.decrypt(ciphertext, nonce)
    except nacl.exceptions.CryptoError as ce:
        # emit failure metric
        if emit_metrics:
            lemma.metrics.emit_failure()

        # raise the exception so we know what happened
        raise

    # emit successful metric
    if emit_metrics:
        lemma.metrics.emit_success()

    return plaintext


def new_key():
    """
    Generate and return a 32-byte random key.

    >>> new_key()
    '\x08i\x98\x07\x92\x9b\x044\x1d-d\x19\x84Y\x11\x7f\xb0\x9c\\\xa8\xc1\xfb<\xafz\xfe3\x91\x81\x8c\x08/'
    """
    return _generate_random_bytes(SECRET_KEY_LEN)


def hexstring_to_bytes(s):
    """
    Given a hex-encoded key, return the key bytes.

    >>> hexstring_to_bytes('08699807929B04341D2D64198459117FB09C5CA8C1FB3CAF7AFE3391818C082F')
    '\x08i\x98\x07\x92\x9b\x044\x1d-d\x19\x84Y\x11\x7f\xb0\x9c\\\xa8\xc1\xfb<\xafz\xfe3\x91\x81\x8c\x08/'
    """
    return base64.b16decode(s)


def bytes_to_hexstring(k):
    """
    Given key bytes, return the hex-encoded key. A-F are always encoded as lowercase.

    >>> bytes_to_hexstring('\x08i\x98\x07\x92\x9b\x044\x1d-d\x19\x84Y\x11\x7f\xb0\x9c\\\xa8\xc1\xfb<\xafz\xfe3\x91\x81\x8c\x08/')
    '08699807929b04341d2d64198459117fb09c5ca8c1fb3caf7afe3391818c082f'
    """
    return base64.b16encode(k).lower()


def _obtain_box(key):
    """
    Setup a SecretBox. If we are given key, always return a new SecretBox
    that uses that key. If no key was passed and a box exists, return that.
    If no key was passed in and no box exists, raise a SecretException.
    """

    # key was passed in
    if key:
        # always override the box
        return nacl.secret.SecretBox(key)

    # no key was passed in
    else:
        if BOX is None:
            # if we don't have a box either, raise an exception
            raise SecretException('No key specified.')
        else:
            # otherwise return the box
            return BOX


def _read_key_from_disk(keypath):
    """
    Reads key from disk and returns the hex-decoded key. New lines
    (if they exist) are stripped.
    """

    # read key from disk
    encoded_secret_key = __builtin__.open(keypath).read()

    # strip newlines if they exist
    hexkey = encoded_secret_key.strip('\n')

    # decode hex-encoding and return key bytes
    return hexstring_to_bytes(hexkey)


def _generate_random_bytes(n):
    """
    Uses operating system source of randomness to generate and return an
    n-byte random number.

    >>> _generate_random_bytes(24)
    'H\x17\x04\xb3\x0b\x9e8\x82\xa8\x86\xf3\xb7\xe2\x14\x89\xff\x0e8\xf24+\xec\xec\xba'
    """

    return os.urandom(n)


class SecretException(Exception):
    """
    SecretException is raised whenever an error occurs when sealing or opening
    a SecretBox.
    """

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)
