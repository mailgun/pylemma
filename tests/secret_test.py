from lemma import secret

from . import *

from mock import patch
from nose.tools import assert_equal, assert_not_equal, assert_raises
from nose.tools import nottest


def test_initialize():
    # setup
    secret.initialize(SECRET_KEY)

    # check
    assert_equal(secret.SECRET_KEY, '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
                                    '\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f')


@patch('lemma.secret._generate_random_bytes')
def test_encrypt_decrypt_cylce(grb):
    # setup
    secret.initialize(SECRET_KEY)

    # mock _generate_random_bytes return value
    grb.return_value = '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17'

    # setup values we expect for seal cycle
    expected_ciphertext = '\x58\x83\x62\xb1\x16\xc2\xd9\x0c\xcb\x90\x9f\x20\x10\x98\xc2\x13\x36\x9a\x54\x23\xa8\xe6\x82\x72\xd4\x44\xae'
    expected_nonce = '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17'

    # test seal cycle
    got_ciphertext, got_nonce = secret.seal('hello, box!')

    # check seal cycle
    assert_equal(expected_ciphertext, got_ciphertext)
    assert_equal(expected_nonce, got_nonce)

    # setup values we expect for open cycle
    expected_plaintext = 'hello, box!'

    # test open cycle
    got_plaintext = secret.open(got_ciphertext, got_nonce)

    # check open cycle
    assert_equal(expected_plaintext, got_plaintext)


@patch('lemma.secret._generate_random_bytes')
def test_encrypt_decrypt_cylce_with_key(grb):
    # setup
    secret.initialize()

    # test that we fail at sealing and opening if no key was ever given
    with assert_raises(secret.SecretException) as e:
        secret.seal('hello, box!')
        secret.open('', '\x00'*24)

    # mock _generate_random_bytes return value
    grb.return_value = '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17'

    # setup values we expect for seal cycle
    expected_ciphertext = '\x88\x37\x9b\xd1\x21\x8c\x53\x52\xda\x46\x5d\x7e\xce\x64\x1a\x10\x69\x6a\xd0\x9a\x48\xae\x0c\x05\x25\xa8\x9e'
    expected_nonce = '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17'

    # test seal cycle
    got_ciphertext, got_nonce = secret.seal('hello, box!', key='\x00'*32)

    # check seal cycle
    assert_equal(expected_ciphertext, got_ciphertext)
    assert_equal(expected_nonce, got_nonce)

    # setup values we expect for open cycle
    expected_plaintext = 'hello, box!'

    # test open cycle
    got_plaintext = secret.open(got_ciphertext, got_nonce, key='\x00'*32)

    # check open cycle
    assert_equal(expected_plaintext, got_plaintext)
