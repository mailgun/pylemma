from os.path import join, abspath, dirname


def fixtures_path():
    return join(abspath(dirname(__file__)), "fixtures")


def fixture_file(name):
    return join(fixtures_path(), name)


def skip_if_asked():
    from nose import SkipTest
    import sys
    if "--no-skip" not in sys.argv:
        raise SkipTest()


HTTPSIGN_KEY = fixture_file("httpsign.key")
SECRET_KEY = fixture_file("secret.key")
