"""
Module metrics provides methods used to emit real time metrics to statsd. This
module requires that it be initialized before it can be used.

>>> from lemma import metrics
>>> metrics.init('localhost', 8125, 'lemma')
"""
import statsd
import socket

# module level statsd client instance: `statsd.StatsClient`. According to the
# documentation this is thread safe.
client = None

# send all metrics by default
DEFAULT_SAMPLE_RATE = 1


def initialize(host, port, prefix=None):
    """
    Initialize statsd client. Metrics will be emitted to the provided host and
    port. An optional prefix can also be passed in to be prepended to all metrics.
    """
    global client

    # if no prefix is given, prefix it with lemma.machine_hostname
    if not prefix:
        hostname = socket.gethostname()
        hostname.replace('.', '_')

        prefix = 'lemma.{}'.format(hostname)

    client = statsd.StatsClient(host, port, prefix=prefix)


def emit_success(prefix=None):
    """
    Emits success metric to statsd. A prefix is required and should
    reflect the component being monitored.

    >>> import lemma.metrics
    >>> lemma.metrics.emit_success('component.heartbeat')
    """

    if prefix:
        _inc('{}.success'.format(prefix))
        return
    _inc('success')


def emit_failure(prefix=None):
    """
    Emits failure metric to statsd. A prefix is required and
    should reflect the component being monitored.

    >>> import lemma.metrics
    >>> lemma.metrics.emit_failure('component.signature')
    """

    if prefix:
        _inc('{}.failure'.format(prefix))
        return

    _inc('failure')


def _inc(stat, count=1, rate=DEFAULT_SAMPLE_RATE):
    """
    Increment a counter for a provided metric.
    """

    if not client:
        return
    client.incr(stat, count, rate)


def _metrics(fn):
    def wrapper(*arg, **kw):
        try:
            result = fn(*arg, **kw)
            emit_failure() if result is False else emit_success()
            return result
        except:
            emit_failure()
            raise
    return wrapper
