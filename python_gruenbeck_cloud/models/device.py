"""Model of a Gruenbeck-cloud device"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from datetime import datetime

from ..exceptions import GruenbeckError

@dataclass
class Device:
    """Model for a Device."""
    type: int
    hasError: bool
    id: str
    series: str
    serialNumber: str
    name: str
    register: bool
    hardwareVersion: str = ""
    lastService: datetime.date = None
    mode: int = 0
    nextRegeneration: datetime.datetime = None
    nominalFlow: float = 0.0
    rawWater: float = 0.0
    softWater: float = 0.0
    softwareVersion: str = ""
    timeZone: str = ""
    unit: int = 0
    startup: datetime.date = None
    errors: str = ""
    salt: str = ""
    water: str = ""

    def __init__(self, data: dict[str, Any]) -> None:
        """Initialize an empty Gruenbeck device class.
        
        Args:
        ----
            data: The full API response from a WLED device.
        
        Raises:
        ------
            GruenbeckError: In case the given API response is incomplete in a
                way that a Device object cannot be constructed from it.
        """
        # Check if all needed elements are in the passed dict, else raise an Error
        if any(
            k not in data and data[k] is not None
            for k in ("type", "hasError", "id", "series", "serialNumber", "name", "register")
        ):
            msg = "Gruenbeck data is incomplete, cannot construct device object"
            raise GruenbeckError(msg)
        
        if "softliq" not in data["series"].lower():
            msg = f"Provided device ist not a softliq-device: {data['series']}"
            raise GruenbeckError(msg)
        
        self.updateFromDict(data)

    def updateFromDict(self, data: dict[str, Any]) -> None:
        """Return Device object from Gruenbeck-cloud API response.
        
        Args:
        ----
            data: Update the device object with the data received from the
            Gruenbeck-cloud API.
        
        Returns:
        -------
            The updated Device object.
        """
        if _type := data.get("type"):
            self.type = int(data["type"])
        
        if "hasError" in data:
            self.hasError = bool(data["hasError"])
        
        if _id := data.get("id"):
            self.id = str(data["id"])
        
        if _series := data.get("series"):
            self.series = str(data["series"])
        
        if _serialNumber := data.get("serialNumber"):
            self.serialNumber = str(data["serialNumber"])
        
        if _name := data.get("name"):
            self.name = str(data["name"])
        
        if "register" in data:
            self.register = bool(data["register"])
        
        if _hardwareVersion := data.get("hardwareVersion"):
            self.hardwareVersion = str(data["hardwareVersion"])
        
        if _lastService := data.get("lastService"):
            self.lastService = datetime.fromisoformat(data["lastService"]).date()
        
        if _mode := data.get("mode"):
            self.mode = int(data["mode"])
        
        if _timeZone := data.get("timeZone"):
            self.timeZone = str(data["timeZone"])
        
        if _nextRegeneration := data.get("nextRegeneration"):
            self.nextRegeneration = datetime.fromisoformat(data["nextRegeneration"]+self.timeZone)
        
        if _nominalFlow := data.get("nominalFlow"):
            self.nominalFlow = float(data["nominalFlow"])
        
        if _rawWater := data.get("rawWater"):
            self.rawWater = float(data["rawWater"])
        
        if _softWater := data.get("softWater"):
            self.softWater = float(data["softWater"])
        
        if _softwareVersion := data.get("softwareVersion"):
            self.softwareVersion = str(data["softwareVersion"])
        
        if _unit := data.get("unit"):
            self.unit = int(data["unit"])
        
        if _startup := data.get("startup"):
            self.startup = datetime.fromisoformat(data["startup"]).date()
        
        if _errors := data.get("errors"):
            self.errors = str(data["errors"])
        
        if _salt := data.get("salt"):
            self.salt = str(data["salt"])
        
        if _water := data.get("water"):
            self.water = str(data["water"])
