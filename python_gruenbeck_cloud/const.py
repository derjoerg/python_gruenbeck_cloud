"""Asynchronous Python client for the Gruenbeck API in the cloud."""

from __future__ import annotations

USER_AGENT = f"PythonGruenbeckCloud"

LOGIN_HOST = "gruenbeckb2c.b2clogin.com"
LOGIN_PATHS = {
    "step1": "/a50d35c1-202f-4da7-aa87-76e51a3098c6/b2c_1a_signinup/oauth2/v2.0/authorize",
    "step2": "/SelfAsserted",
    "step3": "/api/CombinedSigninAndSignup/confirmed",
    "step4": "/oauth2/v2.0/token",
}

API_HOST = "prod-eu-gruenbeck-api.azurewebsites.net"
API_PATH = "/api/devices"
API_VERSION = "2020-08-03"

REQUEST_VARS = {
    "Accept-Encoding": "br, gzip, deflate",
    "Connection": "keep-alive",
    "Accept-Language": "de-de",
    "x-client-Ver": "0.8.0",
    "state": "NjkyQjZBQTgtQkM1My00ODBDLTn3MkYtOTZCQ0QyQkQ2NEE5",
    "client_info": "1",
    "response_type": "code",
    "request_type": "RESPONSE",
    "grant_type": "authorization_code",
    "code_challenge_method": "S256",
    "x-app-name": "Grünbeck",
    "x-client-OS": "14.3",
    "x-app-ver": "1.2.1",
    "scope": "https://gruenbeckb2c.onmicrosoft.com/iot/user_impersonation openid profile offline_access",
    "x-client-SKU": "MSAL.iOS",
    "x-client-CPU": "64",
    "client-request-id": "F2929DED-2C9D-49F5-A0F4-31215427667C",
    "redirect_uri": "msal5a83cc16-ffb1-42e9-9859-9fbf07f36df8://auth",
    "client_id": "5a83cc16-ffb1-42e9-9859-9fbf07f36df8",
    "haschrome": "1",
    "return-client-request-id": "true",
    "x-client-DM": "iPhone",
    "x-ms-PkeyAuth": "1.0",
}
