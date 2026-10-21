# SPDX-License-Identifier: GPL-3.0-or-later

import asyncio
import contextlib
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

import httpx

from ..downloader import Downloader
from ..response import DownloadResponse


class HTTPDownloader(Downloader):
    MAX_DRAIN_SIZE = 64 * 1024
    DRAIN_TIMEOUT = 5.0

    def __post_init__(self):
        auth = None
        if self._settings.url.username and self._settings.url.password:
            auth = (self._settings.url.username, self._settings.url.password)

        base_url = str(self._settings.url)
        if not base_url.endswith("/"):
            base_url += "/"

        http_limits = httpx.Limits(
            max_connections=256,
            max_keepalive_connections=32,
            keepalive_expiry=5,
        )

        client_certificate = None
        if self._settings.client_certificate:
            if self._settings.client_private_key:
                client_certificate = (
                    self._settings.client_certificate,
                    self._settings.client_private_key,
                )
            else:
                client_certificate = self._settings.client_certificate

        transport_params = {
            "verify": self._settings.verify_ca_certificate,
            "http1": True,
            "http2": not self._settings.http2_disable,
            "limits": http_limits,
            "retries": 5,
        }

        if client_certificate:
            transport_params["cert"] = client_certificate

        proxy_mounts: dict[str, httpx.AsyncHTTPTransport] = {}
        for scheme in ("http://", "https://"):
            proxy = self._settings.proxy.for_scheme(scheme)
            scheme_params = transport_params.copy()
            if proxy:
                scheme_params["proxy"] = httpx.Proxy(proxy)

            proxy_mounts[scheme] = httpx.AsyncHTTPTransport(**scheme_params)

        self._httpx = httpx.AsyncClient(
            base_url=base_url,
            auth=auth,
            timeout=httpx.Timeout(
                15,
                connect=30,
                read=60,
            ),
            follow_redirects=True,
            mounts=proxy_mounts,
            max_redirects=5,
            headers={
                "Accept-Encoding": "identity",
                "Cache-Control": "no-cache",
                "Pragma": "no-cache",
                "User-Agent": self._settings.user_agent,
            },
        )

    async def aclose(self):
        await self._httpx.aclose()

    def aiter_bytes(self, response: httpx.Response):
        def func():
            if hasattr(response, "aiter_raw") and not getattr(
                response, "is_stream_consumed", False
            ):
                return response.aiter_raw(chunk_size=self.STREAM_CHUNK_SIZE)
            return response.aiter_bytes(chunk_size=self.STREAM_CHUNK_SIZE)

        return func

    async def _drain_response(self, response: httpx.Response, size: int | None) -> None:
        if getattr(response, "is_stream_consumed", False) or getattr(
            response, "is_closed", False
        ):
            return

        is_error_status = response.is_client_error or response.is_server_error
        if not is_error_status and (size is None or size > self.MAX_DRAIN_SIZE):
            return

        drained = 0
        stream_iter = (
            response.aiter_raw()
            if hasattr(response, "aiter_raw")
            else response.aiter_bytes()
        )
        async with contextlib.aclosing(stream_iter) as raw_stream:
            async for chunk in raw_stream:
                drained += len(chunk)
                if drained >= self.MAX_DRAIN_SIZE:
                    break

    @asynccontextmanager
    async def stream(self, source_path: Path):
        stack = contextlib.AsyncExitStack()
        http_response: httpx.Response | None = None
        size: int | None = None
        response: DownloadResponse
        try:
            http_response = await stack.enter_async_context(
                self._httpx.stream("GET", str(source_path))
            )

            date: datetime | None = None
            last_modified = http_response.headers.get("Last-Modified")
            if last_modified:
                try:
                    date = parsedate_to_datetime(last_modified)
                    if date is not None and date.tzinfo is None:
                        date = date.replace(tzinfo=timezone.utc)
                except (TypeError, ValueError, IndexError):
                    date = None

            try:
                content_length = http_response.headers.get("Content-Length")
                size = int(content_length) if content_length is not None else None
            except (TypeError, ValueError):
                size = None

            response = DownloadResponse(
                missing=http_response.is_client_error,
                error=(
                    f"HTTP/{http_response.status_code}"
                    if http_response.is_server_error
                    else None
                ),
                date=date,
                size=size,
                _stream=self.aiter_bytes(http_response),
            )
        except httpx.RemoteProtocolError as ex:
            # https://github.com/encode/httpx/discussions/2056
            server_disconnected = bool(ex.args) and "Server disconnected" in str(
                ex.args[0]
            )

            response = DownloadResponse(
                _stream=None,
                retry=server_disconnected,
                error=str(ex) if not server_disconnected else None,
            )
        except Exception as ex:  # pylint: disable=W0718
            response = DownloadResponse(
                _stream=None,
                error=f"{ex.__class__.__qualname__}: {str(ex)}",
            )

        try:
            yield response
        finally:
            if http_response is not None:
                with contextlib.suppress(Exception, asyncio.TimeoutError):
                    await asyncio.wait_for(
                        self._drain_response(http_response, size),
                        timeout=self.DRAIN_TIMEOUT,
                    )
            with contextlib.suppress(Exception):
                await stack.aclose()
