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

- getRecords() is overridden to append the Android-replay "sync
  acknowledge" sequence after the standard sync. OMRON Connect
  Android, upon connecting to a device that is advertising
  manuf-data byte 1 = 0x41 ("new data, not yet acked"), follows a
  three-session pattern within a single BLE connection:

    Session 1 (the legacy omblepy flow):
      startTx -> read settings -> write 0x54 (34 bytes) ->
      write 0x80 (16-byte timestamp commit, byte 4 = 0x01) -> endTx

    Session 2 (records-acknowledge, new in this driver):
      startTx -> write 0x54 (24 bytes, with bytes 22-23 forced to
      0x40/0x80 - Android's "ack" sentinel) -> endTx
      [optionally preceded inside the same session by an
      opcode-0x03 Flash dump request (addr 0x00073000,
      len 0x00009000 -> ~38 KiB / 157 chunks framed as
      `fe 01 f2 ...` with a `fe 01 e2 ...` terminator, payload
      discarded); off by default, see syncFlagAckIncludeDump]

    Session 3 (commit ack, new in this driver):
      startTx -> write 0x54 (same 24 bytes) ->
      write 0x80 (16-byte timestamp commit, byte 4 = 0x01,
      with a freshly-stamped local time) -> endTx

  Without sessions 2-3 the device leaves the "new data" flag at 0x41
  even though endTransmission returned 0x00 and records persisted to
  CSV (the omron-syncd daemon already works around this via X-counter
  debounce, but this closes the loop properly on the device side).
  The session-2 dump itself is decorative on EBK firmware - dropping
  it cuts post-record exchange from ~20 s to ~1 s with no effect on
  the flag flip - so we default it off; see ADV_FLAG_BRIEF.md for
  the full investigation.
"""

import asyncio
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

    # Constant 32-bit Flash address & length used by the Android-replay
    # sync-flag acknowledgement (see _sendBlobDumpSyncAck below). These
    # values are byte-identical across every captured Android sync.
    _BLOB_DUMP_ADDR            = 0x00073000
    _BLOB_DUMP_LEN             = 0x00009000  # 36864 bytes (~158 chunks)
    # Master toggle for the post-sync ack (sessions 2 + 3). Set to False
    # to skip the entire ack and fall back to the legacy session-1-only
    # behaviour (records still save to CSV; the device's adv "new data"
    # flag stays at 0x41, i.e. the omron-syncd daemon must rely on its
    # X-counter debounce to avoid re-trigger loops).
    enableSyncFlagAck          = True
    # Sub-toggle for the ~38 KiB Flash blob dump (`0x03` opcode at
    # addr 0x00073000). On EBK this dump completes in ~20 s on Linux's
    # BlueZ stack (vs. ~1 s on Android); empirically the *closing*
    # 24-byte 0x54 (`40 80`) + 16-byte 0x80 commit pair is what
    # actually flips the device's adv flag and the dump itself is
    # decorative on EBK firmware - confirmed by an A/B test where
    # syncFlagAckIncludeDump=False still flipped a freshly-taken
    # measurement's status from 0x41 to 0x01 within a single
    # connection. We keep the dump helper around (and the toggle)
    # so we can re-enable it cheaply if a future firmware update
    # ever requires it.  Has no effect when enableSyncFlagAck = False.
    syncFlagAckIncludeDump     = False

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

    async def getRecords(self, btobj, useUnreadCounter, syncTime):
        """Run the standard sync (session 1: settings + commit + endTx
        via the parent implementation) and then issue Android's full
        post-sync acknowledge: session 2 (24-byte 0x54 write + endTx,
        optionally preceded by a 0x03 Flash dump - see
        syncFlagAckIncludeDump) and session 3 (24-byte 0x54 write +
        fresh 16-byte 0x80 timestamp commit + endTx). Without
        sessions 2-3 the device leaves its BLE-advertising "new data"
        status flag at 0x41 (rather than flipping to 0x01) even though
        endTransmission returned 0x00 and records were persisted to
        CSV. Failures of the ack are best-effort and do not affect
        the returned record set.
        """
        records = await super().getRecords(btobj, useUnreadCounter, syncTime)
        if self.enableSyncFlagAck:
            try:
                await self._sendBlobDumpSyncAck(btobj)
            except Exception as e:
                logger.warning(
                    f"sync-flag ack failed: {e!r}; "
                    f"records were saved successfully."
                )
        return records

    async def _sendBlobDumpSyncAck(self, btobj,
                                   totalTimeoutS=30.0,
                                   idleTimeoutS=2.0):
        """Replay Android's post-sync acknowledge sequence so the
        device clears its BLE-advertising "new data" flag (manuf-data
        byte 1) from 0x41 back to 0x01.

        Sequence (within a single BLE connection, after the parent's
        getRecords closed session 1):

          session 2:
            startTx
            [optional, gated by self.syncFlagAckIncludeDump]
              TX> opcode 0x03 Flash blob read (~38 KiB / ~157 chunks
                  framed as `fe 01 f2 ...` with a `fe 01 e2 ...`
                  terminator; payload discarded)
            TX> write_req addr=0x0054 len=0x18
                  data = first 24 bytes of cachedSettings, bytes
                         22-23 forced to 0x40, 0x80 ("acked"
                         sentinel emitted by every captured Android
                         24-byte 0x54 write).  On EBK reads, byte
                         22 is always 0x40; byte 23 is 0x80 when
                         the device is idle/synced and a low-bit
                         value (0x01 in the captured new-data syncs)
                         when a new measurement is pending - so this
                         write is effectively "force byte 23 to 0x80
                         to ack the pending measurement".
            endTx

          session 3:
            startTx
            TX> write_req addr=0x0054 len=0x18  (same 24 bytes)
            TX> write_req addr=0x0080 len=0x10
                  data = 16-byte timestamp commit, preamble[0:8]
                         from cachedSettings' time-sync slice with
                         byte 4 = 0x01 (commit-to-flash flag),
                         followed by current local time (year-2000,
                         month, day, hour, min, sec), sum-of-bytes
                         checksum, 0x00 pad.  Android writes a fresh
                         local-time stamp here every sync; the
                         preamble[4] = 0x01 is what actually triggers
                         the device to commit the freshly-acked sync
                         state to flash and clear the adv flag.
            endTx

        Wire format of the dump request (always identical):

            0c 03 00 07 30 00 00 00 90 00 00 a8
            ^^ ^^ ^----- addr32 ----^ ^---- len32 ----^ ^^ ^^
            |  |                                        |  CRC
            |  opcode (Flash blob read)                 pad
            total len (12 bytes)

        Address 0x00073000 is the per-sync index/header region in the
        device's Flash; routine Android syncs only read this single
        block. (Initial post-pair syncs also read 0x00010000..0x0006a000
        in 11 contiguous 0x9000-byte chunks; we do not replay those -
        they appear to fetch the full ECG/AFib history and are not
        load-bearing for the flag flip.)

        The dump itself is decorative on EBK firmware - empirically
        verified by an A/B test where syncFlagAckIncludeDump=False
        still flipped a freshly-taken measurement's status from 0x41
        to 0x01 within a single connection, in ~1 s of post-record
        traffic vs ~20 s with the dump. Hence the default; we keep
        the helper for cheap re-enablement if a firmware update ever
        requires it.
        """
        # open session 2 (matches Android's session-2 boundary)
        await btobj.startTransmission()

        if self.syncFlagAckIncludeDump:
            await self._dumpAndDrain(btobj, totalTimeoutS, idleTimeoutS)
        else:
            logger.debug(
                "sync-flag ack: dump phase disabled "
                "(syncFlagAckIncludeDump=False); going straight to "
                "the closing 0x54/0x80 writes."
            )

        # build the 24-byte "ack" payload shared by sessions 2 and 3.
        # requires the cached settings buffer that the parent's
        # getRecords populated (only present when syncTime or
        # useUnreadCounter was true; both are true in the daemon and
        # in the typical CLI invocation -n -t).
        cachedSettings = getattr(self, "cachedSettingsBytes", None)
        if not cachedSettings or len(cachedSettings) < 24:
            logger.warning(
                "sync-flag ack: no cachedSettingsBytes available "
                "(invoked without --newRecOnly/--timeSync?); "
                "skipping post-dump 0x54/0x80 writes - the adv flag "
                "may stay at 0x41."
            )
            await btobj.endTransmission()
            return

        sessionAckBytes = bytearray(cachedSettings[0:24])
        # Android's "post-sync ack" sentinel - bytes 22-23 forced to
        # 0x40, 0x80 in every captured 24-byte 0x54 write. On EBK
        # reads, byte 22 is always 0x40; byte 23 is 0x80 when the
        # device is idle/synced and a low-bit value (0x01 in the
        # captured new-data syncs) when a new measurement is pending.
        # Forcing byte 23 to 0x80 in this write is what the device
        # treats as "host has acknowledged the new data".
        sessionAckBytes[22] = 0x40
        sessionAckBytes[23] = 0x80
        logger.debug(
            f"sync-flag ack session-2 closer: 0x54 24B "
            f"= {bytes(sessionAckBytes).hex()}"
        )

        # session 2 closing write: 24-byte 0x54 write, then endTx.
        # btBlockSize = len so it goes out as a single ATT write
        # request (matches Android exactly; the device rejects multi-
        # block writes here with endTx status 0xe5).
        await btobj.writeContinuousEepromData(
            self.settingsWriteAddress,
            bytes(sessionAckBytes),
            btBlockSize = len(sessionAckBytes),
        )
        await btobj.endTransmission()

        # session 3: same 24-byte 0x54 write, then a fresh 16-byte
        # 0x80 timestamp commit, then endTx. The 0x80 commit's
        # preamble[4] = 0x01 is the actual flag-flip trigger - the
        # device commits the freshly-acked sync state to flash and
        # clears its adv "new data" status flag from 0x41 to 0x01.
        await btobj.startTransmission()

        await btobj.writeContinuousEepromData(
            self.settingsWriteAddress,
            bytes(sessionAckBytes),
            btBlockSize = len(sessionAckBytes),
        )

        # build the 16-byte commit. preserve the 8-byte device-info
        # preamble from the most recent time-sync read (cachedSettings
        # at settingsTimeSyncBytes), force byte 4 = 0x01, and stamp
        # the current local time. This may move the device's RTC by
        # ~1-2 s relative to session 1's commit (matching Android,
        # which also writes a fresh local-time stamp here ~1-2 s
        # after its session-1 commit). Doing this regardless of the
        # --timeSync flag is intentional: the 0x01 commit-to-flash
        # flag is what triggers the adv flag flip, and Android writes
        # a fresh time here on every successful sync.
        tsSlice = cachedSettings[slice(*self.settingsTimeSyncBytes)]
        if len(tsSlice) < 8:
            raise ValueError(
                f"cached time-sync slice too short for 0x80 commit: "
                f"{len(tsSlice)} bytes"
            )
        preamble = bytearray(tsSlice[0:8])
        preamble[4] = 0x01
        nowLocal = datetime.datetime.now()
        commitBytes = bytearray(preamble)
        commitBytes += bytes([
            nowLocal.year - 2000, nowLocal.month, nowLocal.day,
            nowLocal.hour, nowLocal.minute, nowLocal.second,
        ])
        commitBytes.append(sum(commitBytes) & 0xFF)  # checksum
        commitBytes.append(0x00)                       # pad
        assert len(commitBytes) == 0x10
        logger.debug(
            f"sync-flag ack session-3 commit: 0x80 16B "
            f"= {bytes(commitBytes).hex()} "
            f"(now={nowLocal.strftime('%Y-%m-%d %H:%M:%S')} local)"
        )

        await btobj.writeContinuousEepromData(
            self.settingsWriteAddress + self.settingsTimeSyncBytes[0],
            bytes(commitBytes),
            btBlockSize = len(commitBytes),
        )

        await btobj.endTransmission()

    async def _dumpAndDrain(self, btobj, totalTimeoutS, idleTimeoutS):
        """Issue the constant 12-byte opcode-0x03 Flash blob read and
        drain the streaming `fe 01 ...` notifications until the `e2`
        terminator chunk arrives (preferred), idleTimeoutS seconds
        elapse with no new chunk (fallback - device finished streaming
        but never sent the terminator), or totalTimeoutS seconds elapse
        from the request (safety net - device is hung).

        Must be called inside an open transmission session (between
        btobj.startTransmission() and btobj.endTransmission()) so the
        standard CRC-checking RX callback is already installed; this
        helper temporarily replaces it with a non-validating dump
        callback for the duration of the streaming response, then
        restores the standard callback before returning.

        IMPORTANT: we MUST NOT restore the standard RX callback while
        the device is still streaming dump chunks. The standard callback
        runs an XOR-CRC check across the whole packet and would raise
        on every `fe 01 ...` chunk it sees. Hence the idle-timeout
        fallback - the BlueZ stack on Linux is empirically ~10x slower
        at draining BLE notifications than the Android stack we
        observed in capture (~10 chunks/s vs ~150 chunks/s), and on
        EBK firmware we sometimes do not see the `e2` terminator at
        all.
        """
        cmd = bytearray()
        cmd.append(0x0c)                                  # total length = 12
        cmd.append(0x03)                                  # opcode (Flash blob read)
        cmd += self._BLOB_DUMP_ADDR.to_bytes(4, 'big')    # 32-bit BE address
        cmd += self._BLOB_DUMP_LEN.to_bytes(4, 'big')     # 32-bit BE length
        cmd.append(0x00)                                  # padding byte
        crc = 0
        for b in cmd:
            crc ^= b
        cmd.append(crc)                                   # XOR-CRC
        assert len(cmd) == 12 and cmd[-1] == 0xa8, (
            f"sync-ack command bytes drifted from spec: {bytes(cmd).hex()}"
        )

        # locate the live bleak client. omblepy.py runs as the entry-
        # point script and stashes the BleakClient as a module-level
        # global; the btobj's class lives in that same module, so
        # sys.modules gives us the right reference regardless of
        # whether omblepy was invoked as a script (`python omblepy.py`)
        # or imported.
        bleClientHost = sys.modules[btobj.__class__.__module__]
        bleClient = bleClientHost.bleClient
        rxUUID = btobj.deviceRxChannelUUIDs[0]
        txUUID = btobj.deviceTxChannelUUIDs[0]

        # the standard _callbackForRxChannels expects regular Omron
        # framing (with XOR-CRC across the whole packet) and would
        # raise on the `fe 01 ...` blob frames. Take over the channel
        # for the duration of the dump.
        await btobj._disableRxChannelNotifyAndCallback()

        loop = asyncio.get_event_loop()
        terminatorEvent = asyncio.Event()
        chunkCount = 0
        totalBytes = 0
        lastChunkTime = loop.time()

        def _dumpCallback(charOrHandle, rxBytes):
            nonlocal chunkCount, totalBytes, lastChunkTime
            chunkCount += 1
            totalBytes += len(rxBytes)
            lastChunkTime = loop.time()
            # debug-log first few chunks, then every 25th, plus the
            # terminator if we ever see one. keeps the log readable
            # without losing visibility on dump progress.
            isTerm = (len(rxBytes) >= 3
                      and rxBytes[0] == 0xfe
                      and rxBytes[1] == 0x01
                      and rxBytes[2] == 0xe2)
            if chunkCount <= 3 or chunkCount % 25 == 0 or isTerm:
                head = bytes(rxBytes[:8]).hex() if rxBytes else ""
                logger.debug(
                    f"sync-ack chunk #{chunkCount} sz={len(rxBytes)} "
                    f"head={head} term={isTerm}"
                )
            if isTerm:
                terminatorEvent.set()

        await bleClient.start_notify(rxUUID, _dumpCallback)
        # send command FIRST, then wait. write_gatt_char(response=False)
        # matches Android's ATT Write Cmd (0x52).
        try:
            await bleClient.write_gatt_char(txUUID, bytes(cmd), response=False)
        except Exception:
            # if the write itself fails, restore standard notify and bail
            try:
                await bleClient.stop_notify(rxUUID)
            except Exception:
                pass
            await btobj._enableRxChannelNotifyAndCallback()
            raise

        # drain loop. exits on:
        #   1. terminator chunk seen (preferred: clean dump)
        #   2. idleTimeoutS elapsed since last chunk arrived
        #      (device finished streaming, just no `e2` terminator)
        #   3. totalTimeoutS elapsed since the request was sent
        #      (safety net - we then assume the device is hung and
        #      hope endTx works anyway)
        deadline = loop.time() + totalTimeoutS
        lastChunkTime = loop.time()  # reset after the write
        exitReason = "?"
        try:
            while True:
                if terminatorEvent.is_set():
                    exitReason = f"terminator (chunk #{chunkCount})"
                    break
                now = loop.time()
                if now > deadline:
                    exitReason = (f"total timeout {totalTimeoutS:.1f}s "
                                  f"(received {chunkCount} chunks)")
                    break
                idleFor = now - lastChunkTime
                if chunkCount > 0 and idleFor > idleTimeoutS:
                    exitReason = (f"idle {idleFor:.1f}s after "
                                  f"{chunkCount} chunks")
                    break
                # short poll; using sleep(0.05) costs at most 50ms of
                # extra latency at the very end.
                await asyncio.sleep(0.05)
            logger.info(
                f"sync-flag ack drained: {chunkCount} chunks "
                f"({totalBytes} bytes); exit={exitReason}"
            )
        finally:
            try:
                await bleClient.stop_notify(rxUUID)
            except Exception as e:
                logger.debug(f"stop_notify on sync-ack channel failed: {e!r}")

        # short settle delay so any in-flight notifications finish
        # before we re-register the CRC-checking callback. without this
        # the very last dump chunk could land on the standard callback
        # and trip its XOR-CRC check.
        await asyncio.sleep(0.2)

        # restore the standard CRC-checking callback so subsequent
        # writes/reads (including endTransmission) see the 8100/8f00
        # acks via _waitForRxOrRetry.
        await btobj._enableRxChannelNotifyAndCallback()

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
