import asyncio
import dataclasses
import json
import logging
from http import HTTPStatus
from typing import Any, Dict, Optional

import aiohttp
from aiohttp.client import ClientTimeout

DEFAULT_N_HTTP_RETRIES = 5
DEFAULT_TIMEOUT = 15

DEFAULT_GATEWAY_URL = "https://gw.playground-v2.starkex.co/v2/gateway"

logger = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class BadRequest(Exception):
    status_code: int
    text: str

    def __repr__(self) -> str:
        return f"HTTP error ocurred. Status: {str(self.status_code)}. Text: {self.text}"


@dataclasses.dataclass(frozen=True)
class PlaygroundGatewayClient:
    """
    Handles all communication between the StarkEx playground player and the StarkEx gateway.

    :param gateway_url: URL of the StarkEx gateway.
    :type gateway_url: str
    :param n_retries: Number of times the client should retry requests before giving up.
    :type n_retries: int
    :param session_timeout: Timeout (in seconds) for establishing client connection.
    :type session_timeout: int
    """

    gateway_url: str
    n_retries: int = DEFAULT_N_HTTP_RETRIES
    session_timeout: int = DEFAULT_TIMEOUT

    async def _send_request(self, send_method: str, url: str, data: Optional[str] = None):
        """
        Sends HTTP request to the StarkEx gateway.

        If all n_retries attempts fail, raise an exception (the last response defines the error
        message).
        """
        n_retries_left = self.n_retries
        while True:
            n_retries_left -= 1
            try:
                async with aiohttp.TCPConnector() as conn:
                    async with aiohttp.ClientSession(
                        connector=conn, timeout=ClientTimeout(total=self.session_timeout)
                    ) as session:
                        async with session.request(send_method, url, data=data) as response:
                            text = await response.text()
                            if response.status != HTTPStatus.OK:
                                raise BadRequest(status_code=response.status, text=text)
                            return text
            except aiohttp.ClientError:
                if n_retries_left <= 0:
                    raise
                logger.error("ClientConnectorError, retrying...", exc_info=True)
            except BadRequest as e:
                if n_retries_left <= 0:
                    raise
                logger.error(f"BadRequest: {e!r}. Retrying...")
            await asyncio.sleep(1)

    async def get_first_unused_tx_id(self) -> int:
        """
        Queries the StarkEx gateway for the next available transaction ID.
        """
        url = self.gateway_url + "/testing/get_first_unused_tx_id"
        return int(await self._send_request(send_method="GET", url=url))

    async def send_add_tx_request(self, add_tx_request_dict: Dict[str, Any]):
        """
        Submits transaction to the StarkEx gateway.
        """
        url = self.gateway_url + "/add_transaction"
        return await self._send_request(
            send_method="POST", url=url, data=json.dumps(add_tx_request_dict)
        )
