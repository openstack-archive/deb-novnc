#!/usr/bin/env python

'''
A WebSocket to TCP socket proxy with support for "wss://" encryption.
Copyright 2011 Joel Martin
Licensed under LGPL version 3 (see docs/LICENSE.LGPL-3)

You can make a cert/key with openssl using:
openssl req -new -x509 -days 365 -nodes -out self.pem -keyout self.pem
as taken from http://docs.python.org/dev/library/ssl.html#certificates

'''

import Cookie
import optparse
import socket
import sys
import time

import wsproxy

from nova import flags
from nova import log as logging
from nova import rpc
from nova import utils


FLAGS = flags.FLAGS
flags.DEFINE_integer('vnc_proxy_idle_timeout', 180,
                     'Seconds before idle connection destroyed')
flags.DEFINE_flag(flags.HelpFlag())
flags.DEFINE_flag(flags.HelpshortFlag())
flags.DEFINE_flag(flags.HelpXMLFlag())


class NovaWebSocketProxy(wsproxy.WebSocketProxy):
    def __init__(self, *args, **kwargs):
        self.register_nova_listeners()
        wsproxy.WebSocketProxy.__init__(self, *args, **kwargs)

    def register_nova_listeners(self):
        self.tokens = {}

        class TopicProxy():
            @staticmethod
            def authorize_vnc_console(context, **kwargs):
                print "Received a token: %s" % kwargs
                self.tokens[kwargs['token']] =  \
                    {'args': kwargs, 'last_activity': time.time()}

        self.conn = rpc.create_connection(new=True)
        self.conn.create_consumer(
                'vncproxy',
                TopicProxy)

        def delete_expired_tokens():
            now = time.time()
            to_delete = []
            for k, v in self.tokens.items():
                if now - v['last_activity'] > FLAGS.vnc_proxy_idle_timeout:
                    to_delete.append(k)

            for k in to_delete:
                del self.tokens[k]

        self.conn.consume_in_thread()
        utils.LoopingCall(delete_expired_tokens).start(1)

    def new_client(self):
        """
        Called after a new WebSocket connection has been established.
        """
        cookie = Cookie.SimpleCookie()
        cookie.load(self.headers.getheader('cookie'))
        token = cookie['token'].value
        if not token in self.tokens:
            raise Exception("Invalid Token")

        # Get connection info
        host = self.tokens[token]['args']['host']
        port = int(self.tokens[token]['args']['port'])
        # Connect to the target
        self.msg("connecting to: %s:%s" % (
                 host, port))
        tsock = self.socket(host, port,
                connect=True)

        if self.verbose and not self.daemon:
            print(self.traffic_legend)

        # Start proxying
        try:
            self.do_proxy(tsock)
        except:
            if tsock:
                tsock.shutdown(socket.SHUT_RDWR)
                tsock.close()
                self.vmsg("%s:%s: Target closed" %(
                    host, port))
            raise


if __name__ == '__main__':
    usage = "\n    %prog [options]"
    usage += " [source_addr:]source_port target_addr:target_port"
    usage += "\n    %prog [options]"
    usage += " [source_addr:]source_port -- WRAP_COMMAND_LINE"
    parser = optparse.OptionParser(usage=usage)
    parser.add_option("--verbose", "-v", action="store_true",
            help="verbose messages and per frame traffic")
    parser.add_option("--flagfile", "-f", default=None,
            help="Nova flagfile")
    parser.add_option("--record",
            help="record sessions to FILE.[session_number]", metavar="FILE")
    parser.add_option("--daemon", "-D",
            dest="daemon", action="store_true",
            help="become a daemon (background process)")
    parser.add_option("--cert", default="self.pem",
            help="SSL certificate file")
    parser.add_option("--key", default=None,
            help="SSL key file (if separate from cert)")
    parser.add_option("--ssl-only", action="store_true",
            help="disallow non-encrypted connections")
    parser.add_option("--web", default=None, metavar="DIR",
            help="run webserver on same port. Serve files from DIR.")
    parser.add_option("--wrap-mode", default="exit", metavar="MODE",
            choices=["exit", "ignore", "respawn"],
            help="action to take when the wrapped program exits "
            "or daemonizes: exit (default), ignore, respawn")
    (opts, args) = parser.parse_args()

    # Sanity checks
    if len(args) < 1:
        parser.error("Too few arguments")
    if sys.argv.count('--'):
        opts.wrap_cmd = args[1:]
    else:
        opts.wrap_cmd = None
        if len(args) > 1:
            parser.error("Too many arguments")

    if opts.ssl_only and not os.path.exists(opts.cert):
        parser.error("SSL only and %s not found" % opts.cert)

    # Parse host:port and convert ports to numbers
    if args[0].count(':') > 0:
        opts.listen_host, opts.listen_port = args[0].rsplit(':', 1)
    else:
        opts.listen_host, opts.listen_port = '', args[0]

    try:
        opts.listen_port = int(opts.listen_port)
    except:
        parser.error("Error parsing listen port")

    # Dummy values that wsproxy expects
    opts.target_host = 'ignore'
    opts.target_port = 'ignore'

    # Setup flags
    utils.default_flagfile()
    FLAGS(sys.argv)

    # FIXME - the proxy base class does not recognize the flagfile
    # option so remove if present
    if  opts.__dict__.get('flagfile'):
        del opts.__dict__['flagfile']

    # Create and start the NovaWebSockets proxy
    server = NovaWebSocketProxy(**opts.__dict__)
    server.start_server()
