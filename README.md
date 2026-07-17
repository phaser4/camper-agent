# Camper Firmware

This repository contains the ESP-IDF bring-up firmware for the Seeed Studio XIAO ESP32-C6 camper monitor.

The current bring-up focuses on two early subsystems:

* bring up a SIM7080G over UART and try to activate cellular data at boot
* scan BLE advertisements for the Victron BMV-712
* log concise target-device details such as device address, RSSI, and manufacturer data

## Build

1. Install ESP-IDF 6.x.
2. Open an ESP-IDF shell in this folder.
3. Set the target:

```powershell
idf.py set-target esp32c6
```

4. Adjust firmware settings in `menuconfig`:

```powershell
idf.py menuconfig
```

Navigate to `Component config -> Camper Firmware`.

Set at least:

* the Victron target settings when you have them
* the cellular APN
* the required MQTT broker hostname, username, and password when you are
  ready to test HiveMQ publishing

The current LTE bring-up now powers the modem rail from XIAO `D0` / `GPIO0`
before talking to it, and expects the UART wiring on the default XIAO ESP32-C6
pin pair:

* XIAO `D0` / GPIO0 -> DFR0535 `OUT1 EN`
* XIAO `D1` / GPIO1 -> SIM7080G HAT `PWR` / `PWRKEY` control input
* XIAO `D6` / GPIO16 -> SIM7080G `RXD`
* XIAO `D7` / GPIO17 -> SIM7080G `TXD`

5. Build, flash, and monitor:

```powershell
idf.py build flash monitor
```

## What to look for

On boot, the firmware starts BLE scanning immediately, runs one telemetry
collection pass, and queues whichever metrics are currently available. The
current collector tries to read the latest Victron BLE battery-monitor values
first, while leaving hooks for future backup-battery and environment sensors.

The queued telemetry path now uses a dedicated `TelemetryCollector` class for
sampling, a separate fixed-capacity `TelemetryQueue` class for buffering, and a
dedicated `MqttPublisher` class for modem-side MQTT upload. A background task
collects again every 2 hours. A separate background task wakes the modem every
4 hours, publishes the current queued telemetry batch, and only removes those
samples from the queue after a successful publish. Failed LTE or MQTT attempts
leave the queue intact for the next retry.

For HiveMQ Cloud, place a local untracked copy of `isrgrootx1.pem` at
`main/isrgrootx1.pem`. The firmware embeds that local PEM so it can check for
the modem-side CA file at boot and upload it to the SIM7080 filesystem
automatically when it is missing or when the modem firmware does not support
reliable file-existence probing. The firmware now assumes the fixed
broker-side settings already agreed for this project: TLS on port `8883`, CA
filename `isrgrootx1.pem`, topic `camper/raven/telemetry`, client id
`camper-raven`, and the known-good SIM7080G cipher suites `0x0035` and
`0x002F`.

The BLE logs still provide the first pass for discovering likely Victron packets in the camper without dumping full raw advertisement payloads. Once you capture repeatable packets that look like the BMV-712, the next step is to add Victron Instant Readout decoding on top of those advertisement payloads.
