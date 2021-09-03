"""
Module secret can be used to encrypt/decrypt authenticated messages.
See docs/secret.rst for more details.
"""
import base64
import os
try:
    import builtins
except ImportError:
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
    The keypath passed must also be the path to base64-encoded key on disk.
    New lines will be stripped and not considered part of the key.
    """

    global SECRET_KEY, BOX

    # no key passed in
    if keypath is None:
        SECRET_KEY = None
        BOX = None
        return

    # try and load shared secret from disk
    try:
        SECRET_KEY = _read_key_from_disk(keypath)
    except IOError as ioe:
        SECRET_KEY = None
        BOX = None
        raise SecretException('Unable to read key from disk: {}'.format(ioe))

    # initialize the secret box with key bytes
    initialize_with_key(SECRET_KEY)


def initialize_with_key(keybytes=None):
    """
    Initializes module with given keybytes. Here the passed in key must be the
    key bytes themself and not the base64-encoded key.

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
    try:
        SECRET_KEY = keybytes
        BOX = nacl.secret.SecretBox(SECRET_KEY)
    except Exception as e:
        raise SecretException('Unable to initialize SecretBox with given '
            'key: {}: {}'.format(keybytes, e))


def seal(plaintext, key=None):
    """
    Given some plaintext, seal will encrypt and MAC the resulting ciphertext.
    The ciphertext and a nonce is returned on successful encryption.

    The nonce is not secret, but is required to decrypt the ciphertext.

    If a key is passed in, that key will be used to seal the plaintext. This
    key must be the key bytes, not the base64-encoded key. Use the
    encodedkey_to_key function to convert a base64-encoded key into a key.

    >>> ciphertext, nonce = seal('hello, box!')
    >>> print bytes_to_encodedstring(ciphertext)
    'WINisRbC2QzLkJ8gEJjCEzaaVCOo5oJy1ESu'
    >>> print bytes_to_encodedstring(nonce)
    'AAECAwQFBgcICQoLDA0ODxAREhMUFRYX'
    """

    # generate nonce
    nonce = _generate_random_bytes(NONCE_LEN)

    # get a box, if key is passed in, use that to setup box
    box = _obtain_box(key)

    # seal the message inside the box
    encrypted_message = box.encrypt(plaintext, nonce)

    # return the sealed message, a dict with the ciphertext and nonce
    return encrypted_message.ciphertext, encrypted_message.nonce


@lemma.metrics._metrics
def open(ciphertext, nonce, key=None, metrics_prefix=None):
    """
    Given ciphertext and a nonce, open will authenticate that the ciphertext
    has not been tampered with and return the decrypted plaintext.

    If a key is passed in, that key will be used to seal the plaintext. This key
    must be the key bytes, not the base64-encoded key.

    >>> ciphertext = encodedstring_to_bytes('WINisRbC2QzLkJ8gEJjCEzaaVCOo5oJy1ESu')
    >>> nonce = encodedstring_to_bytes('AAECAwQFBgcICQoLDA0ODxAREhMUFRYX')
    >>> open(ciphertext, nonce)
    'hello, box!'
    """

    # get a box, if key is passed in, use that to setup box
    box = _obtain_box(key)

    # open the box and retrieve the message
    try:
        plaintext = box.decrypt(ciphertext, nonce)
    except:
        # raise the exception so we know what happened
        raise

    return plaintext


def new_key():
    """
    Generate and return a 32-byte random key.

    >>> new_key()
    '\x08i\x98\x07\x92\x9b\x044\x1d-d\x19\x84Y\x11\x7f\xb0\x9c\\\xa8\xc1\xfb<\xafz\xfe3\x91\x81\x8c\x08/'
    """
    return _generate_random_bytes(SECRET_KEY_LEN)


def encodedstring_to_bytes(s):
    """
    Given a base64-encoded key, return the key bytes.

    >>> encodedstring_to_bytes('s7z5mRzlul51w7ZSdpZjNZi7HjPp+Lfe')
    '\xb3\xbc\xf9\x99\x1c\xe5\xba^u\xc3\xb6Rv\x96c5\x98\xbb\x1e3\xe9\xf8\xb7\xde'
    """
    return base64.b64decode(s)


def bytes_to_encodedstring(k):
    """
    Given key bytes, return the base64-encoded key.

    >>> bytes_to_encodedstring('\xb3\xbc\xf9\x99\x1c\xe5\xba^u\xc3\xb6Rv\x96c5\x98\xbb\x1e3\xe9\xf8\xb7\xde')
    's7z5mRzlul51w7ZSdpZjNZi7HjPp+Lfe'
    """

    return base64.b64encode(k)


def _obtain_box(key):
    """
    Setup a SecretBox. If we are given key, always return a new SecretBox
    that uses that key. If no key was passed and a box exists, return that.
    If no key was passed in and no box exists, raise a SecretException.
    """

    # key was passed in
    if key:
        try:
            # always override the box
            return nacl.secret.SecretBox(key)
        except Exception as e:
            raise SecretException('Unable to initialize SecretBox with '
                'key: {}: {}'.format(key, e))

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
    Reads key from disk and returns the base64-decoded key. New lines
    (if they exist) are stripped.
    """

    # read key from disk
    encoded_secret_key = __builtin__.open(keypath).read()

    # strip newlines if they exist
    encoded_key = encoded_secret_key.strip('\n')

    # decode base64-encoding and return key bytes
    return encodedstring_to_bytes(encoded_key)


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
