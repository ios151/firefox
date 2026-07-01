"""Local proxy servers (HTTP CONNECT + SOCKS5) that egress through a
Firefox IP Protection Fastly node.

For every client connection we open a TLS connection to a Fastly node
(``<host>:2499``), issue an HTTP ``CONNECT <target>`` with the current
proxy pass in ``Proxy-Authorization: Bearer <jwt>``, then splice bytes
in both directions.
"""
from __future__ import annotations

import asyncio
import random
import ssl
import struct
from typing import Optional

from .guardian import GuardianClient

FASTLY_CONNECT_TIMEOUT = 20


class NodePicker:
    """Chooses a Fastly node for a country preference."""

    def __init__(self, client: GuardianClient, country: Optional[str] = None):
        self.client = client
        self.country = (country or "").upper() or None
        self._by_country: dict[str, dict] = {}

    def refresh(self) -> None:
        self._by_country = self.client.nodes_by_country()
        if not self._by_country:
            raise RuntimeError("no Fastly nodes in server list")
        if self.country and self.country not in self._by_country:
            raise RuntimeError(
                f"country {self.country!r} not available; choices: "
                + ", ".join(sorted(self._by_country))
            )

    def _pool(self) -> list[tuple[str, int]]:
        if not self._by_country:
            self.refresh()
        if self.country:
            return list(self._by_country[self.country]["nodes"])
        return [n for v in self._by_country.values() for n in v["nodes"]]

    def pick(self) -> tuple[str, int]:
        return random.choice(self._pool())

    def pick_many(self, n: int) -> list[tuple[str, int]]:
        """Return up to n distinct random nodes (for failover)."""
        pool = self._pool()
        random.shuffle(pool)
        return pool[:n]


class ProxyServer:
    def __init__(
        self,
        client: GuardianClient,
        node_picker: NodePicker,
        host: str = "127.0.0.1",
        http_port: int = 8080,
        socks_port: int = 1080,
        failover: int = 3,
    ):
        self.client = client
        self.picker = node_picker
        self.host = host
        self.http_port = http_port
        self.socks_port = socks_port
        self.failover = max(1, failover)
        self._ssl = ssl.create_default_context()

    # ---- upstream tunnel ---------------------------------------------
    async def _connect_one(self, node_host, node_port, target_host, target_port, jwt):
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                node_host, node_port, ssl=self._ssl, server_hostname=node_host
            ),
            timeout=FASTLY_CONNECT_TIMEOUT,
        )
        target = f"{target_host}:{target_port}"
        req = (
            f"CONNECT {target} HTTP/1.1\r\n"
            f"Host: {target}\r\n"
            f"Proxy-Authorization: Bearer {jwt}\r\n"
            f"\r\n"
        )
        writer.write(req.encode())
        await writer.drain()
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=FASTLY_CONNECT_TIMEOUT)
            if not chunk:
                break
            head += chunk
        status_line = head.split(b"\r\n", 1)[0].decode(errors="replace")
        if " 200 " not in status_line:
            try:
                writer.close()
            except Exception:
                pass
            raise ConnectionError(f"CONNECT via {node_host}: {status_line}")
        leftover = head.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in head else b""
        return reader, writer, leftover, node_host

    async def _open_tunnel(self, target_host: str, target_port: int):
        """Open a tunnel, trying several nodes for resilience."""
        jwt = await asyncio.to_thread(self.client.proxy_pass)
        nodes = self.picker.pick_many(self.failover)
        last_err = None
        for node_host, node_port in nodes:
            try:
                return await self._connect_one(
                    node_host, node_port, target_host, target_port, jwt
                )
            except Exception as e:
                last_err = e
                _log(f"节点 {node_host} 连接失败（{e!r}），尝试下一个")
        raise ConnectionError(f"{len(nodes)} 个节点全部失败: {last_err!r}")

    @staticmethod
    async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        # OSError covers ConnectionError and ssl.SSLError (incl. the benign
        # APPLICATION_DATA_AFTER_CLOSE_NOTIFY seen when a peer tears the TLS
        # session down mid-transfer); CancelledError fires when the sibling
        # direction finishes first and we cancel this one.
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except (OSError, asyncio.IncompleteReadError, asyncio.CancelledError):
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def _splice(self, c_reader, c_writer, u_reader, u_writer, leftover=b""):
        if leftover:
            c_writer.write(leftover)
            await c_writer.drain()
        t1 = asyncio.ensure_future(self._pipe(c_reader, u_writer))
        t2 = asyncio.ensure_future(self._pipe(u_reader, c_writer))
        try:
            _, pending = await asyncio.wait(
                {t1, t2}, return_when=asyncio.FIRST_COMPLETED
            )
        except asyncio.CancelledError:
            pending = {t1, t2}
            raise
        finally:
            # one direction ended -> close both ends so the other unblocks,
            # then cancel and reap it (avoids "Task was destroyed but pending").
            for w in (c_writer, u_writer):
                try:
                    w.close()
                except Exception:
                    pass
            for t in pending:
                t.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)

    # ---- HTTP proxy ---------------------------------------------------
    async def _handle_http(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        try:
            request_line = await reader.readline()
            if not request_line:
                writer.close()
                return
            parts = request_line.decode(errors="replace").split()
            if len(parts) < 3:
                writer.close()
                return
            method, uri, _ = parts[0], parts[1], parts[2]

            # drain request headers
            headers = b""
            while True:
                line = await reader.readline()
                headers += line
                if line in (b"\r\n", b"", b"\n"):
                    break

            if method.upper() == "CONNECT":
                host, _, port = uri.partition(":")
                target_port = int(port or 443)
                await self._connect_and_splice(host, target_port, reader, writer, client_ack=True)
            else:
                # absolute-form: http://host[:port]/path
                host, target_port, rest = _parse_absolute(uri)
                if host is None:
                    writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                    await writer.drain()
                    writer.close()
                    return
                # rebuild origin-form request for upstream target
                first = f"{method} {rest} HTTP/1.1\r\n".encode()
                initial = first + headers
                await self._connect_and_splice(
                    host, target_port, reader, writer, client_ack=False, initial=initial
                )
        except Exception as e:
            try:
                writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                await writer.drain()
            except Exception:
                pass
            _log(f"HTTP 连接出错 {peer}: {e!r}")
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def _connect_and_splice(
        self, host, port, c_reader, c_writer, client_ack, initial=b""
    ):
        u_reader, u_writer, leftover, node = await self._open_tunnel(host, port)
        if client_ack:
            c_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await c_writer.drain()
        if initial:
            u_writer.write(initial)
            await u_writer.drain()
        await self._splice(c_reader, c_writer, u_reader, u_writer, leftover)

    # ---- SOCKS5 proxy -------------------------------------------------
    async def _handle_socks(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        try:
            # greeting
            ver = await reader.readexactly(1)
            if ver != b"\x05":
                writer.close()
                return
            nmethods = (await reader.readexactly(1))[0]
            await reader.readexactly(nmethods)
            writer.write(b"\x05\x00")  # no auth
            await writer.drain()

            # request
            hdr = await reader.readexactly(4)
            _, cmd, _, atyp = hdr
            if cmd != 0x01:  # only CONNECT
                writer.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                writer.close()
                return
            if atyp == 0x01:  # IPv4
                host = ".".join(str(b) for b in await reader.readexactly(4))
            elif atyp == 0x03:  # domain
                ln = (await reader.readexactly(1))[0]
                host = (await reader.readexactly(ln)).decode()
            elif atyp == 0x04:  # IPv6
                raw = await reader.readexactly(16)
                host = ":".join(f"{raw[i]<<8|raw[i+1]:x}" for i in range(0, 16, 2))
            else:
                writer.close()
                return
            port = struct.unpack("!H", await reader.readexactly(2))[0]

            try:
                u_reader, u_writer, leftover, node = await self._open_tunnel(host, port)
            except Exception as e:
                writer.write(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                writer.close()
                _log(f"SOCKS 连接失败 {host}:{port}: {e!r}")
                return
            # success reply
            writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            await self._splice(reader, writer, u_reader, u_writer, leftover)
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        except Exception as e:
            _log(f"SOCKS 连接出错 {peer}: {e!r}")
        finally:
            try:
                writer.close()
            except Exception:
                pass

    # ---- lifecycle ----------------------------------------------------
    async def start(self):
        """Start listeners and return once they're bound (non-blocking)."""
        self.picker.refresh()
        await asyncio.to_thread(self.client.proxy_pass)
        self._http_srv = await asyncio.start_server(
            self._handle_http, self.host, self.http_port
        )
        self._socks_srv = await asyncio.start_server(
            self._handle_socks, self.host, self.socks_port
        )
        _log(f"HTTP 代理  http://{self.host}:{self.http_port}")
        _log(f"SOCKS5 代理 socks5://{self.host}:{self.socks_port}")
        _log(f"出口国家: {self.picker.country or '任意'}")

    async def switch_country(self, country: Optional[str]):
        """Switch egress country without touching the listeners.

        New connections immediately use the new country; already-open
        tunnels keep running until they close on their own.
        """
        picker = NodePicker(self.client, country)
        await asyncio.to_thread(picker.refresh)
        self.picker = picker
        _log(f"出口国家切换为: {picker.country or '任意'}")

    async def stop(self):
        for attr in ("_http_srv", "_socks_srv"):
            srv = getattr(self, attr, None)
            if srv is not None:
                srv.close()
                try:
                    await srv.wait_closed()
                except Exception:
                    pass
                setattr(self, attr, None)

    async def serve(self):
        await self.start()
        async with self._http_srv, self._socks_srv:
            await asyncio.gather(
                self._http_srv.serve_forever(), self._socks_srv.serve_forever()
            )


def _parse_absolute(uri: str):
    # http://host:port/path  ->  (host, port, "/path")
    if "://" not in uri:
        return None, None, None
    scheme, rest = uri.split("://", 1)
    authority, _, path = rest.partition("/")
    path = "/" + path
    host, _, port = authority.partition(":")
    return host, int(port) if port else (443 if scheme == "https" else 80), path


def _log(msg: str):
    print(f"[fxproxy] {msg}", flush=True)
