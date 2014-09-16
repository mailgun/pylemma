import time

import lemma
import expiringdict

from . import *

from mock import patch
from nose.tools import assert_equal, assert_not_equal
from nose.tools import nottest


def test_initialize():
    # setup
    lemma.initialize(TEST_KEY)

    # check
    assert_equal(lemma.SHARED_SECRET, '042DAD12E0BE4625AC0B2C3F7172DBA8')
    assert_not_equal(lemma.NONCE_CACHE, None)


@patch('lemma._get_timestamp')
@patch('lemma._generate_nonce')
def test_sign_request(gn, gt):
    # setup
    lemma.initialize(TEST_KEY)

    # mock _generate_nonce and _get_timestamp function return values
    gn.return_value = '000102030405060708090a0b0c0d0e0f'
    gt.return_value = '1330837567'

    # setup values we expect
    expected_timestamp = '1330837567'
    expected_nonce = '000102030405060708090a0b0c0d0e0f'
    expected_signature = \
        '5a42c21371e8b3a2b50ca1ad72869dc7882aa83a6a2fb13db1bf108d92c6f05f'
    expected_signature_version = "2"

    # test
    got_timestamp, got_nonce, got_signature, got_signature_version = \
        lemma.sign_request('{"hello": "world"}')

    # check
    assert_equal(expected_timestamp, got_timestamp)
    assert_equal(expected_nonce, got_nonce)
    assert_equal(expected_signature, got_signature)
    assert_equal(expected_signature_version, got_signature_version)


@patch('time.time')
@patch('lemma._get_timestamp')
@patch('lemma._generate_nonce')
def test_authenticate_request(gn, gt, tm):
    # setup
    lemma.initialize(TEST_KEY)

    # mock _generate_nonce and _get_timestamp function return values
    gn.return_value = '000102030405060708090a0b0c0d0e0f'
    gt.return_value = '1330837567'
    tm.return_value = 1330837567.0

    # setup values we want to test and results
    auth_tests = [
    {
        # valid request
        "input": {
            "timestamp": "1330837567",
            "nonce": "00000000000000000000000000000001",
            "signature": "23de59b61ad7317e7f4c75a55c0970ad706d688624f30b468ec9f9fe7e9903d7",
            "body": "{\"hello\": \"world\"}",
            "http_verb": None,
            "http_resource_uri": None,
            "headers": None,
            "key": None
        },
        "output": True
    },
    {
        # valid request (with headers)
        "input": {
            "timestamp": "1330837567",
            "nonce": "00000000000000000000000000000002",
            "signature": "9f8c2c6d44e54a4a2fe921a734af5083dff27429529d9af8b359d3b6181ca39c",
            "body": "{\"hello\": \"world\"}",
            "http_verb": None,
            "http_resource_uri": None,
            "headers": {"foo": "bar"},
            "key": None
        },
        "output": True
    },
    {
        # valid request (with with http_verb and http_resource_uri)
        "input": {
            "timestamp": "1330837567",
            "nonce": "00000000000000000000000000000003",
            "signature": "4f6415b3dfd306470617c14abc487807ba8e5bf26e0b57858bbbc9bb19de2923",
            "body": "{\"hello\": \"world\"}",
            "http_verb": "GET",
            "http_resource_uri": "/path?key=value#fragment",
            "headers": None,
            "key": None
        },
        "output": True
    },
    {
        # valid request (with key)
        "input": {
            "timestamp": "1330837567",
            "nonce": "00000000000000000000000000000004",
            "signature": "c8c9a91f00427f95a165eec6a7ccb0ad68d2655decb39aa3c66515b01b86eab4",
            "body": "{\"hello\": \"world\"}",
            "http_verb": None,
            "http_resource_uri": None,
            "headers": None,
            "key": "abc"
        },
        "output": True
    },
    {
        # forged signature
        "input": {
            "timestamp": "1330837567",
            "nonce": "00000000000000000000000000000005",
            "signature": "0000000000000000000000000000000000000000000000000000000000000000",
            "body": "{\"hello\": \"world\"}",
            "http_verb": None,
            "http_resource_uri": None,
            "headers": None,
            "key": None
        },
        "output": False
    },
    {
        # missing param
        "input": {
            "timestamp": "1330837567",
            "nonce": "00000000000000000000000000000006",
            "signature": None,
            "body": "{\"hello\": \"world\"}",
            "http_verb": None,
            "http_resource_uri": None,
            "headers": None,
            "key": None
        },
        "output": False
    }]

    # check
    for i, test in enumerate(auth_tests):
        print 'Testing Input {}: {}'.format(i, test['input'])
        testOutput = lemma.authenticate_request(test['input']['timestamp'],
                                               test['input']['nonce'],
                                               test['input']['body'],
                                               test['input']['signature'],
                                               http_verb=test['input']['http_verb'],
                                               http_resource_uri=test['input']['http_resource_uri'],
                                               headers=test['input']['headers'],
                                               key=test['input']['key'])
        assert_equal(test['output'], testOutput)


@patch('time.time')
def test_check_timestamp(tm):
    # mock timestamp
    tm.return_value = 1330837567.0

    # setup values we want to test and results
    auth_tests = [
    {
        # goldilocks (perfect) timestamp
        "input": {
            "timestamp": "1330837567",
        },
        "output": True
    },
    {
        # old timestamp
        "input": {
            "timestamp": "1330837517",
        },
        "output": False
    },
    {
        # timestamp from future
        "input": {
            "timestamp": "1330837587",
        },
        "output": False
    }]

    # check
    for test in auth_tests:
        testOutput = lemma._check_timestamp(test['input']['timestamp'])
        assert_equal(test['output'], testOutput)


@patch('time.time')
def test_check_nonce(tm):
    # setup
    lemma.initialize(TEST_KEY)

    # setup values we want to test, mock, and results
    auth_tests = [
    {
        # havn't seen before, should not be in cache.
        "input": {
            "nonce": "0",
            "mock_time": 1330837567,
        },
        "output": False
    },
    {
        # seen before, should be in cache.
        "input": {
            "nonce": "0",
            "mock_time": 1330837567,
        },
        "output": True
    },
    {
        # different value, should not be in cache.
        "input": {
            "nonce": "1",
            "mock_time": 1330837567,
        },
        "output": False
    },
    {
        # aged off first value, should not be in cache.
        "input": {
            "nonce": "0",
            "mock_time": 1330837597,
        },
        "output": False
    }]

    # check
    for test in auth_tests:
        # mock time
        tm.return_value = test['input']['mock_time']

        testOutput = lemma._nonce_in_cache(test['input']['nonce'])
        assert_equal(test['output'], testOutput)
