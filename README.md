# ContaShare for Python

Sign in with [ContaShare](https://contashare.com) and read the contact details your customers choose to share with you, plus a
checker for ContaShare webhook signatures. Standard library only, Python 3.9 or later.

```bash
pip install contashare
```

## Sign up and sign in (Flask)

```python
import os
import secrets
from flask import abort, redirect, request, session
from contashare import ContaShare

contashare = ContaShare(
    client_id=os.environ["CONTASHARE_CLIENT_ID"],
    client_secret=os.environ["CONTASHARE_CLIENT_SECRET"],
    redirect_uri=os.environ["CONTASHARE_REDIRECT_URI"],
)

@app.get("/auth/contashare")
def start():
    session["contashare_state"] = secrets.token_hex(20)
    return redirect(contashare.authorize_url(session["contashare_state"]))

@app.get("/auth/contashare/callback")
def callback():
    expected = session.pop("contashare_state", None)
    if not expected or request.args.get("state") != expected:
        abort(400, "That link expired. Try again.")
    if request.args.get("error"):
        return redirect("/login")  # they pressed Cancel

    tokens = contashare.exchange_code(request.args["code"])
    contashare_id = contashare.me(tokens["access_token"])  # free

    user = users.find_by_contashare_id(contashare_id)
    if user is None:
        # New customer: one call (1 credit) returns everything they shared.
        shared = contashare.shared_data(tokens["access_token"]) or {}
        emails = shared.get("emails", [])
        email = next((e for e in emails if e["email_detail"]["is_verified"]), emails[0] if emails else None)
        if email is None:
            abort(422, "Share an email address to sign up.")
        # Never sign someone in to, or link, an account that already has this email address.
        if users.find_by_email(email["email_detail"]["email_address"]):
            abort(409, "Log in with your password instead.")
        user = users.create(contashare_id=contashare_id, email=email["email_detail"]["email_address"])

    # Keep both tokens: you need them to fetch updates when a webhook arrives.
    users.save_tokens(user, tokens["access_token"], tokens["refresh_token"])
    session.clear()
    session["user_id"] = user.id
    return redirect("/dashboard")
```

- `me()` is free. The ID never changes, it is the same for every OAuth client your team owns, and another company gets a
  different one for the same person.
- `shared_data()` returns `None` when there is nothing new since you last called it. Use `get("/api/v1/email", token)` and the
  other list endpoints after that.
- `authorize_url(state, reconfirm=True)` shows the consent screen again, so the customer can share something new.
- Tokens last a year. Call `refresh(refresh_token)` well before then and store the new pair straight away.
- An error answer raises `ContaShareError` with `status` and `body`.

## Webhooks

ContaShare signs every webhook with a `Signature` header. Check it against the **raw** body:

```python
from contashare import verify_webhook_signature

@app.post("/webhooks/contashare")
def webhook():
    if not verify_webhook_signature(request.get_data(), request.headers.get("Signature"), os.environ["CONTASHARE_WEBHOOK_SECRET"]):
        abort(401)
    # Queue a job that calls contashare.get(request.json["resource_url"], that_customers_token) for an update.
    return "", 204
```

The [OAuth guide](https://contashare.com/help/oauth) and [webhooks guide](https://contashare.com/help/webhooks) cover the rest,
and every endpoint is in the [API reference](https://contashare.com/docs/api).

## Testing

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -t .
```

## Licence

MIT. See [LICENSE](LICENSE).
