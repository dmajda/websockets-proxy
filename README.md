WebSockets Proxy
================

<http://github.com/dmajda/websockets-proxy>

The [WebSocket](http://en.wikipedia.org/wiki/WebSockets) protocol is great for low-overhead full-duplex exchange of data between a browser and a server. But it is not a full TCP/IP channel and sometimes you feel this power missing. WebSockets Proxy offers a solution.

WebSockets Proxy is a simple proxy server written in Ruby which can tunnel TCP/IP traffic through WebSockets. A client connects to the proxy via WebSocket from the browser and tells it a host and port it wishes to connect to. The proxy arranges the connection and from now on, all data the client sends via WebSocket will be resent by the proxy to the other end as raw TCP data (and vice versa). Because the WebSocket protocol only allows UTF-8 strings (not binary data) in its messages, all data sent using it must be Base64-encoded.

This code is just a prototype implementation hacked together during few free hours. As such, there are lots of limitations (see below). Consider this just an exploration of an interesting idea.

In the middle of the work I became aware that similar proxy already exists as a part of the [noVNC](http://kanaka.github.com/noVNC/) project. But that proxy is written in C with a Python wrapper, so I decided to publish mine anyway, mainly because it is easier to modify and deploy.

Try It
------

  1. Run the proxy on your local machine:

         ./websocket_proxy.rb -v

     By default, it runs on port 8080 — you can change it using the `-p` option. The `-v` option specifies verbose output. You can also use `-d` to display a lot of annoying debugging messages.

  2. Grab a recent build of Chromium (one which supports [draft-hixie-thewebsocketprotocol-76](http://tools.ietf.org/html/draft-hixie-thewebsocketprotocol-76) version of the WebSocket protocol).

  3. Paste the following code into the JavaScript console:

         ws = new WebSocket("ws://localhost:8080/google.com:80", "websockets-proxy");
         ws.onopen    = function()  { ws.send(btoa("GET /\r\n\r\n"));     };
         ws.onmessage = function(e) { console.log(atob(e.data));          };
         ws.onerror   = function()  { console.log("WebSocket error.")     };
         ws.onclose   = function()  { console.log("Connection closed.");  };

  4. Observe that the proxy connected to google.com:80, sent your "GET /" request there and delivered the response to the browser.

Limitations
-----------

As I wrote above, this is just an exploration, so there are some limitations. They are often easy to fix, so feel free to fork the code and improve it.

  * No support for UDP traffic (only TCP)

  * No support for encrypted connections (wss:// URLs)

  * The `Origin` header is ignored (connections from all origins are allowed)

  * The `Host` header is ignored

  * No tests (TDD would hurt while prototyping)

  * No proper documentation

  * Performance under heavy load is most likely abysmal (each client gets a new thread, data from client's socket is read byte-by-byte, etc.)

  * The code is blissfully unaware of UTF-8

  * Only tested with Ruby 1.8.7

  * JavaScript client library would be helpful
