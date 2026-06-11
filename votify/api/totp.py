import hashlib
import hmac
import logging
from typing import Collection

import httpx

from ..utils import safe_json
from .constants import TOTP_DIGITS, TOTP_PERIOD, TOTP_SECRETS_URL
from .exceptions import VotifyRequestException

logger = logging.getLogger(__name__)


class Totp:
    def __init__(
        self,
        version: str,
        secret: bytes,
    ) -> None:
        self.version = version
        self.secret = secret

    @classmethod
    async def initialize(cls) -> "Totp":
        secrets = None
        try:
            # timeout=10.0 avoids hanging indefinitely if the host is down or slow
            async with httpx.AsyncClient() as client:
                response = await client.get(TOTP_SECRETS_URL, timeout=10.0)
            secrets = safe_json(response)
            if response.status_code != 200 or not secrets:
                secrets = None
        except Exception:
            secrets = None
            
        if not secrets:
            logger.debug("Failed to fetch TOTP_SECRETS_URL due to timeout or upstream error. Utilizing fallback secrets.")
            secrets = {"59":[123,105,79,70,110,59,52,125,60,49,80,70,89,75,80,86,63,53,123,37,117,49,52,93,77,62,47,86,48,104,68,72],"60":[79,109,69,123,90,65,46,74,94,34,58,48,70,71,92,85,122,63,91,64,87,87],"61":[44,55,47,42,70,40,34,114,76,74,50,111,120,97,75,76,94,102,43,69,49,120,118,80,64,78]}

        logger.debug(f"Received TOTP secrets: {secrets}")

        version = max(secrets.keys(), key=int)

        return cls(
            version=version,
            secret=cls.derive(secrets[version]),
        )

    @staticmethod
    def derive(ciphertext: Collection[int]) -> bytes:
        return "".join(
            str(byte ^ ((i % 33) + 9)) for i, byte in enumerate(ciphertext)
        ).encode("ascii")

    def generate(self, timestamp: int) -> str:
        counter = int(timestamp) // 1000 // TOTP_PERIOD
        counter_bytes = counter.to_bytes(8, "big")

        h = hmac.new(self.secret, counter_bytes, hashlib.sha1)
        hmac_result = h.digest()

        offset = hmac_result[-1] & 0x0F
        binary = (
            (hmac_result[offset] & 0x7F) << 24
            | (hmac_result[offset + 1] & 0xFF) << 16
            | (hmac_result[offset + 2] & 0xFF) << 8
            | (hmac_result[offset + 3] & 0xFF)
        )
        result = str(binary % (10**TOTP_DIGITS)).zfill(TOTP_DIGITS)

        logger.debug(f"Generated TOTP code: {result}")

        return result
