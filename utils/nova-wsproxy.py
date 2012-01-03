#!/usr/bin/env python
# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2012 Openstack, LLC.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#!/usr/bin/env python

'''
Websocket proxy that is compatible with Openstack Nova.
Leverages wsproxy.py by Joel Martin
'''

import Cookie
import socket
import sys
import time

try:
    import wsproxy
except Exception as e:
    print ("Missing noVNC.  You must clone novnc from "
           "git://github.com/cloudbuilders/noVNC and make sure that the "
           "noVNC/utils directory is in your path.")
    sys.exit(1)

from nova import context
from nova import flags
from nova import log as logging
from nova import rpc
from nova import utils


FLAGS = flags.FLAGS
flags.DEFINE_boolean('verbose', False,
                     'Verbose messages and per frame traffic')
flags.DEFINE_boolean('record', False,
                     'Record sessions to FILE.[session_number]')
flags.DEFINE_boolean('daemon', False,
                     'Become a daemon (background process)')
flags.DEFINE_string('cert', 'self.pem',
                     'SSL certificate file')
flags.DEFINE_string('key', None,
                     'SSL key file (if separate from cert)')
flags.DEFINE_boolean('ssl_only', False,
                     'Disallow non-encrypted connections')
flags.DEFINE_boolean('source_is_ipv6', False,
                     'Source is ipv6')
flags.DEFINE_string('web', False,
                     'Run webserver on same port. Serve files from DIR.')
flags.DEFINE_string('listen_host', '0.0.0.0',
                     'Host on which to listen for incoming requests')
flags.DEFINE_integer('listen_port', 6080,
                     'Port on which to listen for incoming requests')

flags.DEFINE_flag(flags.HelpFlag())
flags.DEFINE_flag(flags.HelpshortFlag())
flags.DEFINE_flag(flags.HelpXMLFlag())


class NovaWebSocketProxy(wsproxy.WebSocketProxy):
    def __init__(self, *args, **kwargs):
        wsproxy.WebSocketProxy.__init__(self, *args, **kwargs)

    def new_client(self):
        """
        Called after a new WebSocket connection has been established.
        """
        cookie = Cookie.SimpleCookie()
        cookie.load(self.headers.getheader('cookie'))
        token = cookie['token'].value
        ctxt = context.get_admin_context()
        connect_info = rpc.call(ctxt, 'consoleauth',
                                {'method': 'check_token',
                                 'args': {'token': token }})

        if not connect_info:
            raise Exception("Invalid Token")

        host = connect_info['host']
        port = int(connect_info['port'])

        # Connect to the target
        self.msg("connecting to: %s:%s" % (
                 host, port))
        tsock = self.socket(host, port,
                connect=True)

        # Handshake as necessary
        if connect_info.get('internal_access_path'):
            tsock.send("CONNECT %s HTTP/1.1\r\n\r\n" %
                        connect_info['internal_access_path'])
            while True:
                data = tsock.recv(4096, socket.MSG_PEEK)
                if data.find("\r\n\r\n") != -1:
                    if not data.split("\r\n")[0].find("200"):
                        raise Exception("Invalid Connection Info")
                    tsock.recv(len(data))
                    break

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
    if FLAGS.ssl_only and not os.path.exists(FLAGS.cert):
        parser.error("SSL only and %s not found" % FLAGS.cert)

    # Setup flags
    utils.default_flagfile()
    FLAGS(sys.argv)

    # Create and start the NovaWebSockets proxy
    server = NovaWebSocketProxy(listen_host=FLAGS.listen_host,
                                listen_port=FLAGS.listen_port,
                                source_is_ipv6=FLAGS.source_is_ipv6,
                                verbose=FLAGS.verbose,
                                cert=FLAGS.cert,
                                key=FLAGS.key,
                                ssl_only=FLAGS.ssl_only,
                                daemon=FLAGS.daemon,
                                record=FLAGS.record,
                                web=FLAGS.web,
                                target_host='ignore',
                                target_port='ignore',
                                wrap_mode='exit',
                                wrap_cmd=None)
    server.start_server()
