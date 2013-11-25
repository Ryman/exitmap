#!/usr/bin/env python

"""
Module to detect false positives for https://check.torproject.org.
"""

import socks
import socket
import re

try:
    from http.client import HTTPSConnection
except ImportError:
    from httplib import HTTPSConnection

import log
import command

logger = log.getLogger()

targets = [("check.torproject.org", 443)]

def probe( cmd, count=1 ):

    logger.info("This is scan #%d" % count)

    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", 10000)
    socket.socket = socks.socksocket

    local_port = -1
    attempts = 3

    while attempts > 0:
        try:
            h = HTTPSConnection('check.torproject.org', timeout=30)
            h.request('GET', '/')
            response = h.getresponse()
            data = response.read()
            local_port = h.sock.getsockname()[1]
            break
        except Exception as e:
            logger.error("Exception raised, failed to get check.tpo: '%s'" % str(e))

        attempts -= 1

    identifier = "Congratulations. This browser is configured to use Tor."
    m = re.search("<strong>(?P<ip>\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})</strong>", data)
    if m is not None:
        ip = m.group('ip')
    else:
        ip = None

    if not (identifier in data):
        logger.error("Detected false negative.  Full dump below.")
        logger.error(data)
        return (local_port, ip, False)
    else:
        logger.info("Passed the check test.")
        return (local_port, ip, True)

def main():
    """
    Entry point when invoked over the command line.
    """

    probe(command.new(None))

    return 0

if __name__ == "__main__":
    exit(main())
