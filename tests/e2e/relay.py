"""Fake sing-box mixed inbound: reads a CONNECT and splices to a fixed origin.

The launcher dials this as if it were the profile's residential port, so the
harness exercises the launcher's own loopback proxy rather than bypassing it.
Recorded bytes are printed for diagnosing a broken splice.
"""

from __future__ import annotations

import socket
import sys
import threading

ORIGIN = int(sys.argv[2])


def handle(client: socket.socket) -> None:
    try:
        head = b""
        while not head.endswith(b"\r\n\r\n"):
            chunk = client.recv(1)
            if not chunk:
                return
            head += chunk
        method, target = head.split(b"\r\n")[0].split()[:2]
        if method != b"CONNECT":
            client.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            return
        upstream = socket.create_connection(("127.0.0.1", ORIGIN))
        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

        def pump(src: socket.socket, dst: socket.socket) -> None:
            try:
                while True:
                    data = src.recv(65536)
                    if not data:
                        break
                    dst.sendall(data)
            except OSError:
                pass
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

        threading.Thread(target=pump, args=(client, upstream), daemon=True).start()
        pump(upstream, client)
    finally:
        client.close()


def main() -> None:
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", int(sys.argv[1])))
    listener.listen(16)
    while True:
        conn, _ = listener.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
