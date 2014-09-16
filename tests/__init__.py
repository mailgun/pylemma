from os.path import join, abspath, dirname, exists


def fixtures_path():
    return join(abspath(dirname(__file__)), "fixtures")


def fixture_file(name):
    return join(fixtures_path(), name)


def skip_if_asked():
    from nose import SkipTest
    import sys
    if "--no-skip" not in sys.argv:
        raise SkipTest()


TEST_KEY = fixture_file("test.key")
