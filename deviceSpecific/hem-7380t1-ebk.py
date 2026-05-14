"""
Device driver for the Omron HEM-7380T1-EBK (M7 Intelli IT AFib, EU/EBK region).

Differences from the upstream HEM-7380T1 driver (which was tested on -EOSL):

- requiresUnlock = True. The EBK requires a 0x11 + 4-byte random nonce
  unlock command on every connection (not just during initial pairing).
  The 4-byte nonce is generated fresh per-connection; the device echoes
  it back with response 0x91 0x00 + nonce.

- supportsPairing = True / supportsOsBondingOnly = True. The EBK uses
  Just-Works BLE bonding for transport security AND requires the
  application-level 0x11 unlock on top. Initial pairing also requires
  specific EEPROM writes to commit the bond/key to flash, see
  deviceSpecific_pairFinalization() below.

- transmissionBlockSize = 0x10. The EBK accepts only 16-byte EEPROM read
  blocks (the upstream 0x38 / 56 bytes causes the device to ignore the
  request).

- settings*Address populated. Mirrors the layout used by HEM-7361T,
  enabling --newRecOnly and --timeSync. The on-device RTC is updated by
  re-issuing the same 16-byte timestamp write that pair-finalization
  performs (preamble byte 4 = 0x01 + current local-time bytes); this is
  the only write empirically observed to move the device's display
  clock, see deviceSpecific_syncWithSystemTime() below.
"""

import datetime
import logging
import sys

logger = logging.getLogger("omblepy")

sys.path.append('..')
from sharedDriver import sharedDeviceDriverCode


class deviceSpecificDriver(sharedDeviceDriverCode):
    parentService_UUID         = "0000fe4a-0000-1000-8000-00805f9b34fb"
    deviceRxChannelUUIDs       = ["49123040-aee8-11e1-a74d-0002a5d5c51b"]
    deviceTxChannelUUIDs       = ["db5b55e0-aee7-11e1-965e-0002a5d5c51b"]
    deviceUnlock_UUID          = "b305b680-aee7-11e1-a730-0002a5d5c51b"

    requiresUnlock             = True   # 0x11 + 4-byte nonce on every connection
    supportsPairing            = True   # initial pair flow is supported (Just-Works + 0x11 + finalization)
    supportsOsBondingOnly      = True   # OS-level bond is the primary transport-security mechanism

    deviceEndianess            = "little"
    userStartAdressesList      = [0x01C4, 0x0804]
    perUserRecordsCountList    = [100, 100]
    recordByteSize             = 0x10
    transmissionBlockSize      = 0x10

    #settings layout. Unread-records section is 0x22 = 34 bytes, the same
    #size pair-finalization writes back at 0x54 (and which the device acks
    #with endTransmission status 0x00). With shorter (16- or 24-byte) writes
    #at 0x54 in a session that also contains the 0x80 timestamp/commit
    #write, the device returns 0xe5 instead - and the BLE advertising
    #"new data" status flag fails to flip back to 0x01. Reading 34 bytes
    #also matches the OMRON Connect Android app's session-1 read coverage.
    settingsReadAddress        = 0x0010
    settingsWriteAddress       = 0x0054
    settingsUnreadRecordsBytes = [0x00, 0x22]
    settingsTimeSyncBytes      = [0x2C, 0x3C]

    def deviceSpecific_ParseRecordFormat(self, singleRecordAsByteArray):
        rawSys = singleRecordAsByteArray[0]
        if rawSys > 0xE1:
            raise ValueError("record slot is empty")

        recordDict = dict()
        recordDict["sys"] = rawSys + 25
        recordDict["dia"] = singleRecordAsByteArray[1]
        recordDict["bpm"] = singleRecordAsByteArray[2]

        year   = 2000 + (singleRecordAsByteArray[3] & 0x3F)
        flags1 = singleRecordAsByteArray[4] | (singleRecordAsByteArray[5] << 8)
        flags2 = singleRecordAsByteArray[6] | (singleRecordAsByteArray[7] << 8)

        hour              = flags1 & 0x1F
        day               = (flags1 >> 5) & 0x1F
        month             = (flags1 >> 10) & 0x0F
        recordDict["ihb"] = (flags1 >> 14) & 0x01
        recordDict["mov"] = (flags1 >> 15) & 0x01
        second            = min(flags2 & 0x3F, 59)
        minute            = (flags2 >> 6) & 0x3F

        recordDict["datetime"] = datetime.datetime(
            year, month, day, hour, minute, second,
        )
        return recordDict

    # No resetUnreadRecordsCounter() override: the parent's implementation
    # (which only sets bytes 4-7 of the cached unread-records section to the
    # 0x8000 sentinel and echoes the rest unchanged from the device's read
    # response) is enough for the EBK, *provided* the section is 34 bytes
    # wide - matching pair-finalization, which is acked with endTx 0x00.
    # The byte-patching tried earlier (bytes 1/11/15/16/22/23) was a
    # red-herring inherited from the 24-byte working theory.

    def deviceSpecific_syncWithSystemTime(self):
        # Update the cached 16-byte timestamp block at settingsTimeSyncBytes
        # (cached buffer offset 0x2C..0x3B, EEPROM 0x3C..0x4B; written by the
        # shared driver to 0x54+0x2C = 0x80). This mirrors the timestamp write
        # done during pair-finalization: the OMRON Connect Android app issues
        # the exact same 16-byte payload here. Empirically, *only* this write
        # (with preamble byte 4 = 0x01 set) moves the on-device display clock;
        # plain settings writes do not. So --timeSync runs are safe to repeat
        # (e.g. after DST changes) without re-pairing.
        timeSyncSettingsCopy = self.cachedSettingsBytes[slice(*self.settingsTimeSyncBytes)]
        # log the device's currently stored timestamp for visibility
        try:
            year   = 2000 + timeSyncSettingsCopy[8]
            month  = timeSyncSettingsCopy[9]
            day    = timeSyncSettingsCopy[10]
            hour   = timeSyncSettingsCopy[11]
            minute = timeSyncSettingsCopy[12]
            second = timeSyncSettingsCopy[13]
            logger.info(f"device-stored timestamp: {datetime.datetime(year, month, day, hour, minute, second).strftime('%Y-%m-%d %H:%M:%S')}")
        except Exception:
            logger.warning("device-stored timestamp is invalid (will be overwritten)")

        preamble = bytearray(timeSyncSettingsCopy[0:8])
        preamble[4] = 0x01  # commit-to-flash flag, also gates the RTC update
        nowLocal = datetime.datetime.now()
        newTimeBytes = bytearray(preamble)
        newTimeBytes += bytes([
            nowLocal.year - 2000, nowLocal.month, nowLocal.day,
            nowLocal.hour, nowLocal.minute, nowLocal.second,
        ])
        newTimeBytes.append(sum(newTimeBytes) & 0xFF)  # checksum byte
        newTimeBytes.append(0x00)                       # pad
        assert len(newTimeBytes) == 0x10
        self.cachedSettingsBytes[slice(*self.settingsTimeSyncBytes)] = newTimeBytes
        logger.info(f"device clock will be set to {nowLocal.strftime('%Y-%m-%d %H:%M:%S')} (local)")

    async def deviceSpecific_unlock(self, btobj):
        await btobj.unlockWithRandomKey()

    async def deviceSpecific_pairFinalization(self, btobj):
        """Replay the application-level pair-finalization sequence the OMRON
        Connect Android app does, which the device requires in order to commit
        the freshly-established BLE bond and 0x11 unlock-key state to flash.
        Without this, every subsequent reconnection fails with
        'PIN or Key Missing' on the encryption-change event.

        The sequence (observed via HCI snoop, then replayed):
          1. unlock with 0x11 + 4 random bytes + 12 zeros
          2. startTransmission
          3. read settings @ 0x0010, size 0x2c
          4. read last-contact timestamp @ 0x003c, size 0x18
          5. write back the first 0x22 bytes of the read settings to 0x0054
             (this is the actual bond-commit trigger)
          6. write a 16-byte timestamp record (UTC) to 0x0080
          7. endTransmission
        After endTransmission the device terminates the link itself
        (Reason 0x13); the caller is expected to wait for that event.
        """
        await btobj.unlockWithRandomKey()
        await btobj.startTransmission()

        settingsBytes = await btobj.readContinuousEepromData(
            self.settingsReadAddress,
            self.settingsWriteAddress - self.settingsReadAddress,  # 0x44 -> covers 0x10..0x53
            self.transmissionBlockSize,
        )
        # the 0x18-byte block at 0x003c (which is settingsTimeSyncBytes inside
        # the cached buffer) is read here too, so we now have everything we
        # need to construct the writes
        logger.debug(f"pair-finalization: read settings = {bytes(settingsBytes).hex()}")

        # write 1: first 0x22 bytes of settings copied back unchanged
        settingsWriteback = bytes(settingsBytes[0x00:0x22])
        await btobj.writeContinuousEepromData(
            self.settingsWriteAddress,
            settingsWriteback,
            btBlockSize = len(settingsWriteback),  # single packet
        )

        # write 2: 16-byte timestamp block. First 8 bytes are the device-info
        # preamble (`c6 a4 00 00 ?? 00 00 00`); the device returns byte 4 = 0x00
        # but the OMRON Connect Android app overwrites it with 0x01 - empirically
        # this 0x01 flag is what triggers the device to commit the freshly
        # established SMP bond and 0x11 unlock-key state to flash. Without it,
        # subsequent reconnections fail with "PIN or Key Missing".
        # Bytes 8..13 are year-2000/month/day/hour/min/sec; byte 14 is a checksum
        # (sum-of-preceding-bytes mod 256, same convention the 7361T driver uses
        # for time sync); byte 15 is pad.
        # NOTE on timezone: Android writes UTC here; with that the device's
        # display clock ends up running on UTC. Empirically this *initial*
        # write during pair-finalization sets the device's RTC to the
        # transmitted value (subsequent metadata writes during normal syncs
        # do not, which is consistent with users not noticing drift over
        # years of Android use - they manually fix the clock once at first
        # setup). We therefore write *local* time so that, after pairing,
        # the on-device clock immediately matches the user's wall clock.
        tsRead = settingsBytes[self.settingsTimeSyncBytes[0]:self.settingsTimeSyncBytes[1]]
        preamble = bytearray(tsRead[0:8])
        preamble[4] = 0x01  # bond-commit flag (see comment above)
        nowLocal = datetime.datetime.now()
        tsWrite = bytearray(preamble)
        tsWrite += bytes([
            nowLocal.year - 2000, nowLocal.month, nowLocal.day,
            nowLocal.hour, nowLocal.minute, nowLocal.second,
        ])
        tsWrite.append(sum(tsWrite) & 0xFF)
        tsWrite.append(0x00)
        assert len(tsWrite) == 0x10
        await btobj.writeContinuousEepromData(
            self.settingsWriteAddress + self.settingsTimeSyncBytes[0],
            bytes(tsWrite),
            btBlockSize = len(tsWrite),
        )

        await btobj.endTransmission()
        logger.info("pair-finalization complete; awaiting device-initiated disconnect")
        return
