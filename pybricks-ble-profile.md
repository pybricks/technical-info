# Pybricks Bluetooth Low Energy Profile

This document describes the Pybricks Bluetooth Low Energy profile used to
communicate with hubs running Pybricks firmware.

## Profile v1.2.0

The following changes were made since v1.1.0.

#### Pybricks Service

The Pybricks Service has been extend.

##### Pybricks Command/Event Characteristic

- GATT properties: write, notify (write-without-response is no longer supported)

- Clarify that long writes are not supported.

- The characteristic will return an error code when a command fails.

- PBIO_PYBRICKS_STATUS_SHUTDOWN_REQUESTED = 8 is added to the
  PBIO_PYBRICKS_EVENT_STATUS_REPORT flags.

- Application specific error codes:

  - PBIO_PYBRICKS_ERROR_INVALID_COMMAND = 0x80
    - Indicates that an invalid command was requested.

  - PBIO_PYBRICKS_ERROR_BUSY = 0x81
    - Indicates that the command cannot be completed because the resources
      needed are busy doing something else.

- New commands:

  - PBIO_PYBRICKS_COMMAND_START_USER_PROGRAM = 1
      - Requests to start a user program.
      - Parameters:
        - None.
      - Fails with PBIO_PYBRICKS_ERROR_BUSY if a user program is currently running.

  - PBIO_PYBRICKS_COMMAND_START_REPL = 2
      - Requests to start an interactive REPL.
      - Parameters:
        - None.
      - Fails with PBIO_PYBRICKS_ERROR_BUSY if a user program is currently running.

  - PBIO_PYBRICKS_COMMAND_WRITE_USER_PROGRAM_META = 3
      - Requests to write the user program metadata.
      - Parameters:
        - `size`: The size of the user program in user RAM in bytes (32-bit
          unsigned integer).
      - Fails with PBIO_PYBRICKS_ERROR_BUSY if a user program is currently running.

  - PBIO_PYBRICKS_COMMAND_WRITE_USER_RAM = 4
      - Requests to write data to the user RAM.
      - Parameters:
        - `offset`: the offset from the user RAM base address where the payload
          is to be written (32-bit unsigned integer).
        - `payload`: 0 to `max_char_size` - 5 bytes of data to be written.
          (`max_char_size` is read from the hub capabilities characteristic.)
      - Fails with PBIO_PYBRICKS_ERROR_BUSY if a user program is currently running.
      - User program starts at offset 0.
      - Additional user RAM layout/usage may be inferred from the hub
        capabilities characteristic value.

- User program download procedure:
  - Write PBIO_PYBRICKS_COMMAND_WRITE_USER_PROGRAM_META with `size` 0.
  - Write user program starting at `offset` 0 using
    PBIO_PYBRICKS_COMMAND_WRITE_USER_RAM in chunks of `max_char_size`.
  - Write PBIO_PYBRICKS_COMMAND_WRITE_USER_PROGRAM_META with actual user
    program `size`.

##### Pybricks Hub Capabilities Characteristic

- A new characteristic is added to read hub capabilities.
- GATT properties: read
- Value size: 10 bytes
- Parameters:
  - `max_char_size`: The maximum number of bytes that can be written to a
    characteristic without triggering a long write (16-bit unsigned integer).
  - `feature_flags`: A bitwise mask of feature flags (32-bit unsigned integer).
  - `max_user_program_size`: The maximum allowable size of a user program in
    bytes (32-bit unsigned integer).

- Feature flags:
  - PBIO_PYBRICKS_FEATURE_REPL = 1 << 0
    - Indicates that the hub has an interactive REPL.
  - PBIO_PYBRICKS_FEATURE_USER_PROG_FORMAT_MULTI_MPY_V6 = 1 << 1
    - Indicates that the hub supports user programs using the Pybricks
      multi-mpy6 file format.

#### Nordic UART Service

The feature to download and run a program via the Nordic UART Service has
been removed.

#### Device Information Service

##### Software Revision String

For this version of the Pybricks Profile, this is exactly `1.2.0`.


## Profile v1.1.0

The following additions were made since v1.0.0.

### Advertising Data

The scan response now contains a *Service Data* entry with the *PnP ID*
as described in the *Device Information Service*.

### Services

The following services have changed.
#### Device Information Service

The following characteristic is now required.

##### PnP ID

This characteristic identifies the type of device.

The *Vendor ID Source Field* and and *Vendor ID Field* use an existing know ID
for the vendor, for example, for LEGO, the source field will be 0x01 for
*Bluetooth SIG-assigned Device ID* and the vendor ID is 0x0397 (LEGO's CID).

The *Product ID Field* uses the *Hub Type IDs* from local [Assigned Numbers]
document.

[Assigned Numbers]: ./assigned-numbers.md

The *Product Version Field* is the hub variant or 0 if there is no variant.
For example, the MINDSTORMS Robot Inventor hub is variant 1 of the *Technic
Large Hub*.

#### Pybricks Service

The Pybricks Service has been extend.

##### Pybricks Command/Event Characteristic

- PBIO_PYBRICKS_STATUS_SHUTDOWN = 7 is added to the
  PBIO_PYBRICKS_EVENT_STATUS_REPORT flags.

#### Device Information Service

##### Software Revision String

For this version of the Pybricks Profile, this is exactly `1.1.0`.

## Profile v1.0.0

This section describes the requirements for the Pybricks Profile v1.0.0.

### Advertising Data

The advertisement data (connectable, undirected) contains the following:
- Flags
- Incomplete list of service UUIDs containing the Pybricks Service UUID.
- Tx Power Level

The scan response contains the hub name.

### Services

The following GATT services are required.

#### Device Information Service

The standard *Device Information Service* is used to provide information about
the type of device and the software versions. Additional details about this
service can be found in the [official docs].

[official docs]: https://www.bluetooth.com/specifications/specs/device-information-service-1-1/

The following characteristics are required.

##### Firmware Revision String

This characteristic must contain the firmware version in [PEP 440] short form.
For example `1.0.0b4`.

[PEP 440]: https://peps.python.org/pep-0440/

##### Software Revision String

This characteristic must contain the Pybricks Profile version in [SemVer 1.0.0].

For this version of the Pybricks Profile, this is exactly `1.0.0`.

[SemVer 1.0.0]: https://semver.org/spec/v1.0.0.html


#### Nordic UART Service

This service follows the unofficial [Nordic UART Service specification].

This service is connected to the standard I/O of the hub (stdin/stdout) and is
also used for downloading user programs and starting the REPL.

[Nordic UART Service specification]: https://learn.adafruit.com/introducing-the-adafruit-bluefruit-le-uart-friend/uart-service

When a user program is running, this connected to the stdin and stdout.

When a user program is not running, this acts as a channel for downloading
user programs or starting the repl using the following protocol:

- Subscribe to notifications on the Rx characteristic.
- Write the size of the user program (32-bit unsigned integer) to the Tx
  characteristic.
- If the size is 0x20202020 (4 ASCII space characters), then the REPL will be
  started and the procedure ends (this is considered a user program and the
  services becomes the stdio for the REPL).
- Write 100 bytes of the user program to the Tx characteristic (this can be
  divided in smaller chunks if negotiated MTU is < 100).
- Wait for a notification from the Rx characteristic. This will contain a 1-byte
  xor checksum of the 100 bytes that were just written.
- Repeat the previous two steps until the entire program is sent. The last write
  may be less that 100 bytes.
- The user program will start automatically and the service will be connected
  to stdio.

#### Pybricks Service

This service is used to get status updates and to send commands to the hub.

##### Pybricks Command/Event Characteristic

This service must support write and notify and must not require authentication
or authorization.

Notifications contain event messages. The first byte of the payload contains
the event type. The remaining payload depends on the event type.

Event types:

- PBIO_PYBRICKS_EVENT_STATUS_REPORT = 0
  - Payload is 32-bit unsigned integer containing bit flags.
    - PBIO_PYBRICKS_STATUS_BATTERY_LOW_VOLTAGE_WARNING = 0
    - PBIO_PYBRICKS_STATUS_BATTERY_LOW_VOLTAGE_SHUTDOWN = 1
    - PBIO_PYBRICKS_STATUS_BATTERY_HIGH_CURRENT = 2
    - PBIO_PYBRICKS_STATUS_BLE_ADVERTISING = 3
    - PBIO_PYBRICKS_STATUS_BLE_LOW_SIGNAL = 4
    - PBIO_PYBRICKS_STATUS_POWER_BUTTON_PRESSED = 5
    - PBIO_PYBRICKS_STATUS_USER_PROGRAM_RUNNING = 6

Writing to the characteristic sends a command to the hub. The first byte of the
payload is the command type. The remaining payload depends on the command.

Command Types:

- PBIO_PYBRICKS_COMMAND_STOP_USER_PROGRAM = 0
  - Requests to stop the user program.
  - Parameters:
    - None.

Additional notes:

- The standard GAP and GATT services are required for BLE but are not
  strictly part of this profile, so are not covered in this document.
- All binary values are encoded using little-endian byte order.
