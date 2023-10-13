"""Testscript for asynchronous Python client for the Gruenbeck-cloud API"""

import asyncio

from python_gruenbeck_cloud.gruenbeck import Gruenbeck, Device

async def main() -> None:
    """Test script"""
    async with Gruenbeck(
        username="abc",
        password="xyz"
    ) as gruenbeck:
        await gruenbeck.connect()

        if gruenbeck.connected:
            print("Connected")
            devices = await gruenbeck.getDevices()
        else:
            quit()

        def something_updated(device: Device) -> None:
            """Call when Gruenbeck reports a state change"""
            print("Received an update from Gruenbeck")
            print(device)

        # Start listening (not working as expected)
        task = asyncio.create_task(gruenbeck.listen(callback=something_updated))

        print(devices)
        await asyncio.sleep(3600)
        task.cancel()

if __name__ == "__main__":
    asyncio.run(main())
