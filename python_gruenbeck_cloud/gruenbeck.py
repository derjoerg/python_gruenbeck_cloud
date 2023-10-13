"""Asynchronous Python client for the Gruenbeck Cloud API."""

from __future__ import annotations

import asyncio

from dataclasses import dataclass

from typing import TYPE_CHECKING, Any, cast

from aiohttp import ClientSession, ClientWebSocketResponse
from aiohttp.hdrs import METH_POST, METH_GET
import async_timeout
from yarl import URL
import math
import base64
import random
import hashlib
from datetime import datetime

from .const import USER_AGENT, LOGIN_HOST, LOGIN_PATHS, REQUEST_VARS, API_HOST, API_PATH, API_VERSION
from .exceptions import (
    GruenbeckError,
    GruenbeckConnectionError,
    GruenbeckConnectionTimeoutError,
)
from .models.device import Device

if TYPE_CHECKING:
    from typing_extensions import Self

@dataclass
class Gruenbeck:
    """Main class for handling connections with Gruenbeck cloud"""
    username: str
    password: str
    request_timeout: float = 10.0
    session: ClientSession | None = None
    _devices: dict | None = None
    _device: Device | None = None
    _ws: ClientWebSocketResponse | None = None
    _accessToken: str | None = None
    _refreshToken: str | None = None
    _tenant: str | None = None
    _notBefore: datetime.datetime = None
    _expiresOn: datetime.datetime = None
    _close_session: bool = False

    @property
    def connected(self) -> bool:
        """Return if we are connected to the Gruenbeck API
        
        Returns
        -------
            True if we are connected to the Gruenbeck API,
            False otherwise.
        """

        if self._accessToken is None or self._isExpiredToken():
            return False
        
        return True

    def _isExpiredToken(self) -> bool:
        """Check if Token is expired"""

        if self._expiresOn.timestamp() - 60 > datetime.now().timestamp():
            return False
        
        return False

    async def getDevices(self) -> list[str]:
        """Get Devices from Gruenbeck-API."""
        self._devices = {}

        if self.connected:
            await self._getRefreshToken()
            response = await self.__request(uri="")

            for config in response["json"]:
                device = Device(config)

                if device is not None:
                    device = await self.updateDevice(device)
                    self._devices[device.serialNumber] = device

            if len(self._devices) > 0:
                await self._connectWebSocket()
                await self._enterSD(device)
                await self._refreshSD(device)
                return self._devices
            else:
                msg = f"No suitable devices found!"
                raise GruenbeckError(msg) from Exception

        else:
            msg = f"Not connected"
            raise GruenbeckError(msg) from Exception

    async def _getRefreshToken(self) -> None:
        """Refreshes the needed authorization token."""
        headers = {
            "Host": LOGIN_HOST,
            "x-client-SKU": REQUEST_VARS["x-client-SKU"],
            "Accept": "application/json",
            "x-client-OS": REQUEST_VARS["x-client-OS"],
            "x-app-name": REQUEST_VARS["x-app-name"],
            "x-client-CPU": REQUEST_VARS["x-client-CPU"],
            "x-app-ver": REQUEST_VARS["x-app-ver"],
            "Accept-Language": REQUEST_VARS["Accept-Language"],
            "client-request-id": REQUEST_VARS["client-request-id"],
            "User-Agent": USER_AGENT,
            "x-client-Ver": REQUEST_VARS["x-client-Ver"],
            "x-client-DM": REQUEST_VARS["x-client-DM"],
            "return-client-request-id": REQUEST_VARS["return-client-request-id"],
            "cache-control": "no-cache",
        }
        url = URL.build(
            scheme= "https",
            host= LOGIN_HOST,
            path= self._tenant + LOGIN_PATHS["step4"],
            query= {
                "client_id": REQUEST_VARS["client_id"],
                "scope": REQUEST_VARS["scope"],
                "refresh_token": self._refreshToken,
                "client_info": REQUEST_VARS["client_info"],
                "grant_type": "refresh_token",
            }
        )
        response = await self.__request(
            url= url,
            method= METH_POST,
            returnCookies= False,
            returnText= False,
        )
        self._accessToken = response["json"]["access_token"]
        self._refreshToken = response["json"]["refresh_token"]
        self._notBefore = datetime.fromtimestamp(response["json"]["not_before"])
        self._expiresOn = datetime.fromtimestamp(response["json"]["expires_on"])

    async def _enterSD(self, device: Device) -> None:
        """enter SD"""
        headers = {
            "Host": API_HOST,
            "Accept": "application/json, text/plain, */*",
            "User-Agent": USER_AGENT,
            "Accept-Language": REQUEST_VARS["Accept-Language"],
            "Authorization": "Bearer " + self._accessToken,
        }
        await self.__request(
            uri= device.serialNumber + "/realtime/enter",
            method= METH_POST,
            headers= headers,
            returnText= True,
        )
        print("EnterSD")

    async def _refreshSD(self, device: Device) -> None:
        """refresh SD"""
        #await self._ws.send_json('{"protocol":"json","version":1}')
        headers = {
            "Host": API_HOST,
            "Accept": "application/json, text/plain, */*",
            "User-Agent": USER_AGENT,
            "Accept-Language": REQUEST_VARS["Accept-Language"],
            "Authorization": "Bearer " + self._accessToken,
        }
        await self.__request(
            uri= device.serialNumber + "/realtime/refresh",
            method= METH_POST,
            headers= headers,
            returnText= True,
        )
        print("RefreshSD")

    async def _connectWebSocket(self) -> None:
        """Create the needed websocket for the stream info"""
        headers = {
            "Content-Type": "text/plain;charset=UTF-8",
            "Origin": "file://",
            "Accept": "*/*",
            "User-Agent": USER_AGENT,
            "Authorization": "Bearer " + self._accessToken,
            "Accept-Language": REQUEST_VARS["Accept-Language"],
            "cache-control": "no-cache",
            "X-Requested-With": "XMLHttpRequest",
        }
        url = URL.build(
            scheme= "https",
            host= API_HOST,
            path= "/api/realtime/negotiate",
        )
        response = await self.__request(
            url= url,
            method= METH_GET,
            headers= headers,
        )
        wsUrl = response["json"]["url"]
        wsAccessToken = response["json"]["accessToken"]
        headers = {
            "Content-Type": "text/plain;charset=UTF-8",
            "Origin": "file://",
            "Accept": "*/*",
            "User-Agent": USER_AGENT,
            "Authorization": "Bearer " + wsAccessToken,
            "Accept-Language": REQUEST_VARS["Accept-Language"],
            "X-Requested-With": "XMLHttpRequest",
        }
        url = URL.build(
            scheme= "https",
            host= "prod-eu-gruenbeck-signalr.service.signalr.net",
            path= "/client/negotiate",
            query= {
                "hub": "gruenbeck",
            }
        )
        response = await self.__request(
            url= url,
            method= METH_POST,
            headers= headers,
        )
        wsConnectionId = response["json"]["connectionId"]
        headers = {
            "Upgrade": "websocket",
            "Host": "prod-eu-gruenbeck-signalr.service.signalr.net",
            "Origin": "null",
            "Pragma": "no-cache",
            "Cache-Control": "no-cache",
            "User-Agent": USER_AGENT,
        }
        url = URL.build(
            scheme= "wss",
            host= "prod-eu-gruenbeck-signalr.service.signalr.net",
            path= "/client/",
            query= {
                "hub": "gruenbeck",
                "id": wsConnectionId,
                "access_token": wsAccessToken,
            }
        )
        self._ws = await self.session.ws_connect(
            url= url,
            headers= headers,
        )
        await self._ws.send_json('{"protocol":"json","version":1}')

    async def listen(self, callback: Callable[[Device], None]) -> None:
        """Listen for events"""
        if not self._ws or not self.connected:
            msg = "Not connected"
            raise GruenbeckError(msg)
        
        while not self._ws.closed:
            message = await self._ws.receive()
            print(message)

    async def updateDevice(self, device=Device) -> Device:
        response = await self.__request(uri=device.serialNumber)
        #test = await self.__request(uri=device.serialNumber+"/parameters")
        #print(test["json"])
        #test = await self.__request(uri=device.serialNumber+"/measurements/salt")
        #print(test["json"])
        #test = await self.__request(uri=device.serialNumber+"/measurements/water")
        #print(test["json"])
        device.updateFromDict(response["json"])
        headers = {
            "Host": API_HOST,
            "Accept": "application/json, text/plain, */*",
            "User-Agent": USER_AGENT,
            "Authorization": "Bearer " + self._accessToken,
            "Accept-Language": REQUEST_VARS["Accept-Language"],
            "cache-control": "no-cache",
        }
        await self.__request(
            uri= device.serialNumber + "/realtime/refresh",
            method= METH_POST,
            headers= headers,
            returnText= True,
        )
        print("Refresh")
        return device
    
    async def connect(self) -> None:
        """Authenticate to the API and and connect to the WebSocket
        
        Returns
        -------
            GruenbeckError: General problem with the API
            GruenbeckConnectionError: Error occured while communicating with
                the Gruenbeck API via the Websocket
        """
        if self.connected:
            return
        
        if not self._devices:
            await self.authenticate()

    async def authenticate(self) -> None:
        """Authenticate to the API
        """
        await self.__login()

    async def __login(self) -> None:
        challenge = await self.__getCodeChallenge()
        codeVerifier = challenge[0]
        codeChallenge = challenge[1]
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Encoding": REQUEST_VARS["Accept-Encoding"],
            "Connection": REQUEST_VARS["Connection"],
            "Accept-Language": REQUEST_VARS["Accept-Language"],
            "User-Agent": USER_AGENT
        }
        url = URL.build(
            scheme= "https",
            host= LOGIN_HOST,
            path= LOGIN_PATHS["step1"],
            query= {
                "x-client-Ver": REQUEST_VARS["x-client-Ver"],
                "state": REQUEST_VARS["state"],
                "client_info": REQUEST_VARS["client_info"],
                "response_type": REQUEST_VARS["response_type"],
                "code_challenge_method": REQUEST_VARS["code_challenge_method"],
                "x-app-name": REQUEST_VARS["x-app-name"],
                "x-client-OS": REQUEST_VARS["x-client-OS"],
                "x-app-ver": REQUEST_VARS["x-app-ver"],
                "scope": REQUEST_VARS["scope"],
                "x-client-SKU": REQUEST_VARS["x-client-SKU"],
                "code_challenge": codeChallenge,
                "x-client-CPU": REQUEST_VARS["x-client-CPU"],
                "client-request-id": REQUEST_VARS["client-request-id"],
                "redirect_uri": REQUEST_VARS["redirect_uri"],
                "client_id": REQUEST_VARS["client_id"],
                "haschrome": REQUEST_VARS["haschrome"],
                "return-client-request-id": REQUEST_VARS["return-client-request-id"],
                "x-client-DM": REQUEST_VARS["x-client-DM"],
            }
        )
        step1 = await self.__request(
            url,
            METH_GET,
            headers= headers,
            returnCookies= True,
            returnText= True
        )
        start = step1["text"].find("csrf") + 7
        end = step1["text"].find(",", start) - 1
        csrf = step1["text"][start:end]
        start = step1["text"].find("transId") + 10
        end = step1["text"].find(",", start) - 1
        transId = step1["text"][start:end]
        start = step1["text"].find("policy") + 9
        end = step1["text"].find(",", start) - 1
        policy = step1["text"][start:end]
        start = step1["text"].find("tenant") + 9
        end = step1["text"].find(",", start) - 1
        tenant = step1["text"][start:end]
        self._tenant = tenant
        cookieString = "; ".join(str(x)+"="+str(y) for x, y in step1["cookies"].items())
        headers = {
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "X-CSRF-TOKEN": csrf,
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "X-Requested-With": "XMLHttpRequest",
            "Origin": "https://" + LOGIN_HOST,
            "Cookie": cookieString,
            "User-Agent": USER_AGENT,
        }
        url = URL.build(
            scheme= "https",
            host= LOGIN_HOST,
            path= tenant + LOGIN_PATHS["step2"],
            query = {
                "tx": transId,
                "p": policy,
            }
        )
        postParams = {
            "request_type": REQUEST_VARS["request_type"],
            "signInName": self.username,
            "password": self.password,
        }
        step2 = await self.__request(
            url,
            METH_POST,
            headers= headers,
            data= postParams,
            returnCookies= True,
            returnText= True,
        )
        cookieString = "; ".join(str(x)+"="+str(y) for x, y in step2["cookies"].items())
        cookieString += "; x-ms-cpim-csrf=" + csrf
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Encoding": REQUEST_VARS["Accept-Encoding"],
            "Connection": REQUEST_VARS["Connection"],
            "Accept-Language": REQUEST_VARS["Accept-Language"],
            "Cookie": cookieString,
            "User-Agent": USER_AGENT,
        }
        url = URL.build(
            scheme= "https",
            host= LOGIN_HOST,
            path= tenant + LOGIN_PATHS["step3"],
            query = {
                "csrf_token": csrf,
                "tx": transId,
                "p": policy,
            }
        )
        step3 = await self.__request(
            url,
            METH_GET,
            headers= headers,
            returnCookies= False,
            returnText= True,
            allowRedirects= False,
        )
        start = step3["text"].find("code%3d") + 7
        end = step3["text"].find(">here") - 1
        code = step3["text"][start:end]
        headers = {
            "Host": LOGIN_HOST,
            "x-client-SKU": REQUEST_VARS["x-client-SKU"],
            "Accept": "application/json",
            "x-client-OS": REQUEST_VARS["x-client-OS"],
            "x-app-name": REQUEST_VARS["x-app-name"],
            "x-client-CPU": REQUEST_VARS["x-client-CPU"],
            "x-app-ver": REQUEST_VARS["x-app-ver"],
            "Accept-Language": REQUEST_VARS["Accept-Language"],
            "client-request-id": REQUEST_VARS["client-request-id"],
            "x-ms-PkeyAuth": REQUEST_VARS["x-ms-PkeyAuth"],
            "x-client-Ver": REQUEST_VARS["x-client-Ver"],
            "x-client-DM": REQUEST_VARS["x-client-DM"],
            "User-Agent": USER_AGENT,
            "return-client-request-id": REQUEST_VARS["return-client-request-id"],
        }
        url = URL.build(
            scheme= "https",
            host= LOGIN_HOST,
            path= tenant + LOGIN_PATHS["step4"],
        )
        postParams = {
            "client_info": REQUEST_VARS["client_info"],
            "scope": REQUEST_VARS["scope"],
            "code": code,
            "grant_type": REQUEST_VARS["grant_type"],
            "code_verifier": codeVerifier,
            "redirect_uri": REQUEST_VARS["redirect_uri"],
            "client_id": REQUEST_VARS["client_id"],
        }
        step4 = await self.__request(
            url,
            METH_POST,
            headers= headers,
            data= postParams,
            returnCookies= False,
            returnText= False,
        )
        self._accessToken = step4["json"]["access_token"]
        self._refreshToken = step4["json"]["refresh_token"]
        self._notBefore = datetime.fromtimestamp(step4["json"]["not_before"])
        self._expiresOn = datetime.fromtimestamp(step4["json"]["expires_on"])

    async def __getCodeChallenge(self):
        chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        hash = ""
        result = ""

        while (len(hash) == 0) or (hash.find("+") != -1) or (hash.find("/") != -1) or (hash.find("=") != -1) or (result.find("+") != -1) or (result.find("/") != -1):
            result = ""

            for x in reversed(range(0, 64)):
                result += chars[math.floor(random.random() * len(chars))]

            result = base64.b64encode(result.encode('utf-8')).decode('utf-8')
            result = result.replace("=", "")
            hash = base64.b64encode(hashlib.sha256(result.encode('utf-8')).digest()).decode("utf-8")
            hash = hash[0:len(hash) - 1]
        
        return [result, hash]

    async def __request(
            self,
            url: URL | None = None,
            uri: str = "",
            method: str = METH_GET,
            headers: dict[str, Any] | None = None,
            data: dict[str, Any] | None = None,
            returnCookies: bool = False,
            returnText: bool = False,
            allowRedirects: bool = True,
    ) -> Any:
        """Handle requests for Gruenbeck-Cloud
        
        A generic method for sending/handling HTTP requests against the
        Gruenbeck-cloud
        
        Args:
        ----
            url: Request URL.
            method: HTTP method to use for the request.
            headers: Dictionary of headers to send to the Gruenbeck-Cloud
            returnCookies: True if the Cookie-String should be returned
            returnText: True if the Response-Text should be returned instead of
                        the Response-Json
        
        Returns:
        -------
            A Python dictionary with the response from the Gruenbeck-Cloud
        """

        if self.session is None:
            self.session = ClientSession()
            self._close_session = True
        
        if url is None:
            url = URL.build(
                scheme= "https",
                host= API_HOST,
                path= API_PATH,
                query= {
                    "api-version": API_VERSION,
                }
            ).joinpath(uri)
            headers = {
                "Host": API_HOST,
                "Accept": "application/json, text/plain, */*",
                "User-Agent": USER_AGENT,
                "Authorization": "Bearer " + self._accessToken,
                "Accept-Language": REQUEST_VARS["Accept-Language"],
                "cache-control": "no-cache",
            }

        try:
            async with async_timeout.timeout(self.request_timeout):
                response = await self.session.request(
                    method,
                    url,
                    headers=headers,
                    data= data,
                    allow_redirects= allowRedirects,
                )
        except asyncio.TimeoutError as exception:
            msg = f"Timeout occured while connecting to Gruenbeck-Cloud at {url.host}"
            raise GruenbeckConnectionTimeoutError(msg) from exception

        cookies = {}
        text = ""
        json = {}
        
        if returnCookies:

            for c in response.cookies:
                cookies[c] = response.cookies[c].value
            
        if returnText:
            text = await response.text()
        else:
            json = cast(dict[str, Any], await response.json())
            
        return {"cookies": cookies, "text": text, "json": json}

    async def disconnect(self) -> None:
        """Disconnect from the WebSocket of the Gruenbeck-cloud."""
        if not self._ws or not self.connected:
            return
        
        await self._ws.close()
    
    async def close(self) -> None:
        """Close open client (WebSocket) session."""
        await self.disconnect()

        if self.session and self._close_session:
            await self.session.close()

    async def __aenter__(self) -> Gruenbeck:
        """Async enter.
        
        Returns
        -------
            The Gruenbeck object.
        """
        return self

    async def __aexit__(self, *_exc_info: Any) -> None:
        """Async exit.
        
        Args:
        ----
            _exc_info: Exec type.
        """
        await self.close()
