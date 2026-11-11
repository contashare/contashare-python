"""Sign in with ContaShare and read the contact details your customers share, plus a checker for webhook signatures."""

import hashlib
import hmac
import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, Optional, Tuple, Union

__all__ = ["ContaShare", "ContaShareError", "verify_webhook_signature", "DEFAULT_BASE_URL"]

DEFAULT_BASE_URL = "https://contashare.com"

# (method, url, headers, body) -> (status, response body)
Transport = Callable[[str, str, Dict[str, str], Optional[bytes]], Tuple[int, bytes]]


class ContaShareError(Exception):
    """ContaShare answered with an error. ``status`` and ``body`` hold what it said."""

    def __init__(self, status: int, body: Any):
        detail = ""
        if isinstance(body, dict):
            detail = body.get("message") or body.get("error_description") or body.get("error") or ""
        super().__init__(f"ContaShare answered {status}: {detail}".strip())
        self.status = status
        self.body = body


def _urllib_transport(method: str, url: str, headers: Dict[str, str], body: Optional[bytes]) -> Tuple[int, bytes]:
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


class ContaShare:
    """"Sign in with ContaShare" and the ContaShare API, for one OAuth client."""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        base_url: str = DEFAULT_BASE_URL,
        transport: Optional[Transport] = None,
    ):
        if not client_id or not client_secret or not redirect_uri:
            raise ValueError("ContaShare needs client_id, client_secret and redirect_uri.")
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.base_url = base_url.rstrip("/")
        self._transport = transport or _urllib_transport

    def authorize_url(self, state: str, reconfirm: bool = False) -> str:
        """Where to send someone to sign in. Store ``state`` in their session and check it in your callback.

        ``reconfirm`` shows the consent screen again, so they can share something new.
        """
        if not state:
            raise ValueError("authorize_url needs a state: a random value you store in the session and check in your callback.")
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "scope": "",
            "state": state,
        }
        if reconfirm:
            params["reconfirm"] = "true"
        return f"{self.base_url}/oauth/authorize?{urllib.parse.urlencode(params)}"

    def exchange_code(self, code: str) -> Dict[str, Any]:
        """Swaps the code from your callback for an access and refresh token. Do it once, straight away, on your server."""
        return self._token({"grant_type": "authorization_code", "code": code, "redirect_uri": self.redirect_uri})

    def refresh(self, refresh_token: str) -> Dict[str, Any]:
        """Swaps a refresh token for a new pair. The old pair stops working, so store the new one straight away."""
        return self._token({"grant_type": "refresh_token", "refresh_token": refresh_token})

    def me(self, access_token: str) -> str:
        """The ID your company knows this customer by. Free.

        It never changes, it is the same for all your team's OAuth clients, and another company gets a different one for the
        same person: store it and find the customer by it.
        """
        return self.get("/api/v1/me", access_token)["id"]

    def shared_data(self, access_token: str) -> Optional[Dict[str, Any]]:
        """Everything the customer shares with you (1 credit).

        It answers once per customer, then only again when they have shared something new: None means there is nothing new,
        so use the list endpoints instead.
        """
        status, body = self._request("/api/v1/shared-data", access_token)
        if status == 403 and isinstance(body, dict) and body.get("error"):
            return None
        return self._body_or_raise(status, body)

    def get(self, path_or_url: str, access_token: str) -> Any:
        """Any API endpoint, such as a webhook's ``resource_url`` or ``/api/v1/email``."""
        return self._body_or_raise(*self._request(path_or_url, access_token))

    def _request(self, path_or_url: str, access_token: str) -> Tuple[int, Any]:
        url = path_or_url if path_or_url.startswith("http") else f"{self.base_url}{path_or_url}"
        # Without Accept: application/json, ContaShare redirects an unauthorised call to its login page instead of a 401.
        headers = {"Accept": "application/json", "Authorization": f"Bearer {access_token}"}
        status, raw = self._transport("GET", url, headers, None)
        return status, _json(raw)

    def _token(self, fields: Dict[str, str]) -> Dict[str, Any]:
        body = urllib.parse.urlencode({"client_id": self.client_id, "client_secret": self.client_secret, **fields}).encode()
        headers = {"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"}
        status, raw = self._transport("POST", f"{self.base_url}/oauth/token", headers, body)
        return self._body_or_raise(status, _json(raw))

    @staticmethod
    def _body_or_raise(status: int, body: Any) -> Any:
        if status < 200 or status >= 300:
            raise ContaShareError(status, body)
        return body


def _json(raw: bytes) -> Any:
    try:
        return json.loads(raw.decode() or "null")
    except ValueError:
        return None


def verify_webhook_signature(raw_body: Union[bytes, str], signature: Optional[str], secret: str) -> bool:
    """Checks the ``Signature`` header ContaShare sends with every webhook.

    It is the HMAC-SHA256 (hex) of the raw request body, keyed with your webhook secret. Pass the raw body, never JSON you
    parsed and dumped again.
    """
    if not signature or not secret or raw_body is None:
        return False
    body = raw_body.encode() if isinstance(raw_body, str) else raw_body
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)
