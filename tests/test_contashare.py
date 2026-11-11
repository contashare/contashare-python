import hashlib
import hmac
import json
import unittest
import urllib.parse

from contashare import ContaShare, ContaShareError, verify_webhook_signature


class FakeTransport:
    """Answers from a list in turn and records each request."""

    def __init__(self, *answers):
        self.answers = list(answers)
        self.calls = []

    def __call__(self, method, url, headers, body):
        self.calls.append({"method": method, "url": url, "headers": headers, "body": body})
        status, payload = self.answers.pop(0)
        return status, json.dumps(payload).encode()


def client(transport=None, **options):
    return ContaShare(
        client_id="client-123",
        client_secret="secret-456",
        redirect_uri="https://acme.example/auth/contashare/callback",
        transport=transport or FakeTransport(),
        **options,
    )


def query(url):
    return dict(urllib.parse.parse_qsl(urllib.parse.urlparse(url).query))


class ContaShareTest(unittest.TestCase):
    def test_it_sends_people_to_the_consent_screen_with_the_app_details_and_state(self):
        url = client().authorize_url("random-state")

        self.assertTrue(url.startswith("https://contashare.com/oauth/authorize?"))
        self.assertEqual(query(url)["client_id"], "client-123")
        self.assertEqual(query(url)["redirect_uri"], "https://acme.example/auth/contashare/callback")
        self.assertEqual(query(url)["response_type"], "code")
        self.assertEqual(query(url)["state"], "random-state")
        self.assertNotIn("reconfirm", query(url))

    def test_reconfirm_shows_the_consent_screen_again_and_a_state_is_required(self):
        self.assertEqual(query(client().authorize_url("s", reconfirm=True))["reconfirm"], "true")
        with self.assertRaises(ValueError):
            client().authorize_url("")

    def test_it_swaps_the_code_for_tokens_with_the_client_credentials(self):
        transport = FakeTransport((200, {"access_token": "access-1", "refresh_token": "refresh-1", "expires_in": 31536000}))

        tokens = client(transport).exchange_code("the-code")

        self.assertEqual(tokens["access_token"], "access-1")
        self.assertEqual(transport.calls[0]["method"], "POST")
        self.assertEqual(transport.calls[0]["url"], "https://contashare.com/oauth/token")
        self.assertEqual(
            dict(urllib.parse.parse_qsl(transport.calls[0]["body"].decode())),
            {
                "client_id": "client-123",
                "client_secret": "secret-456",
                "grant_type": "authorization_code",
                "code": "the-code",
                "redirect_uri": "https://acme.example/auth/contashare/callback",
            },
        )

    def test_refreshing_swaps_the_pair_and_a_refused_refresh_raises_with_the_reason(self):
        transport = FakeTransport(
            (200, {"access_token": "access-2", "refresh_token": "refresh-2"}),
            (400, {"error": "invalid_grant", "error_description": "The refresh token is invalid."}),
        )
        contashare = client(transport)

        self.assertEqual(contashare.refresh("refresh-1")["refresh_token"], "refresh-2")
        self.assertEqual(dict(urllib.parse.parse_qsl(transport.calls[0]["body"].decode()))["grant_type"], "refresh_token")
        with self.assertRaises(ContaShareError) as raised:
            contashare.refresh("refresh-1")
        self.assertEqual(raised.exception.status, 400)
        self.assertEqual(raised.exception.body["error"], "invalid_grant")

    def test_me_returns_the_id_the_company_knows_the_customer_by_asking_for_json_with_the_token(self):
        transport = FakeTransport((200, {"id": "9f1c2d3e-4b5a-4c6d-8e7f-0a1b2c3d4e5f"}))

        self.assertEqual(client(transport).me("access-1"), "9f1c2d3e-4b5a-4c6d-8e7f-0a1b2c3d4e5f")
        self.assertEqual(transport.calls[0]["url"], "https://contashare.com/api/v1/me")
        self.assertEqual(transport.calls[0]["headers"]["Authorization"], "Bearer access-1")
        self.assertEqual(transport.calls[0]["headers"]["Accept"], "application/json")

    def test_shared_data_returns_the_records_once_none_when_there_is_nothing_new_and_raises_when_refused(self):
        contashare = client(FakeTransport(
            (200, {"emails": [{"id": "email-1"}]}),
            (403, {"error": "You have already fetched bulk shared data for this customer."}),
            (403, {"message": "Your credits have run out."}),
        ))

        self.assertEqual(contashare.shared_data("access-1")["emails"], [{"id": "email-1"}])
        self.assertIsNone(contashare.shared_data("access-1"))
        with self.assertRaisesRegex(ContaShareError, "Your credits have run out"):
            contashare.shared_data("access-1")

    def test_get_follows_a_webhook_resource_url_as_it_is(self):
        transport = FakeTransport((200, {"id": "address-1"}))

        client(transport).get("https://contashare.com/api/v1/address/address-1", "access-1")

        self.assertEqual(transport.calls[0]["url"], "https://contashare.com/api/v1/address/address-1")

    def test_a_customer_token_is_never_sent_to_another_site_as_a_forged_webhook_could_name_one(self):
        transport = FakeTransport()
        contashare = client(transport)

        for url in (
            "https://evil.example/api/v1/address/1",
            "//evil.example/api/v1/address/1",
            "https://contashare.com.evil.example/x",
            "http://contashare.com/api/v1/address/1",
            "https://contashare.com@evil.example/x",
        ):
            with self.assertRaises(ValueError):
                contashare.get(url, "access-1")
        self.assertEqual(transport.calls, [])

    def test_a_base_url_points_it_at_another_contashare(self):
        url = client(base_url="http://localhost:8000/").authorize_url("s")

        self.assertTrue(url.startswith("http://localhost:8000/oauth/authorize?"))


class VerifyWebhookSignatureTest(unittest.TestCase):
    BODY = '{"id":"9b3f8a2e","type":"address","action":"update"}'

    def test_a_signature_made_with_the_secret_over_the_raw_body_is_valid(self):
        signature = hmac.new(b"whsec", self.BODY.encode(), hashlib.sha256).hexdigest()

        self.assertTrue(verify_webhook_signature(self.BODY, signature, "whsec"))
        self.assertTrue(verify_webhook_signature(self.BODY.encode(), signature, "whsec"))

    def test_a_wrong_secret_a_changed_body_or_no_signature_is_refused(self):
        signature = hmac.new(b"whsec", self.BODY.encode(), hashlib.sha256).hexdigest()

        self.assertFalse(verify_webhook_signature(self.BODY, signature, "another-secret"))
        self.assertFalse(verify_webhook_signature(self.BODY.replace("update", "delete"), signature, "whsec"))
        self.assertFalse(verify_webhook_signature(self.BODY, None, "whsec"))
        self.assertFalse(verify_webhook_signature(self.BODY, "", "whsec"))
        self.assertFalse(verify_webhook_signature(self.BODY, signature, ""))


if __name__ == "__main__":
    unittest.main()
