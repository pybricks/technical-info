# Pybricks Bluetooth Low Energy Broadcast/Observe

This document describes the format of messages used by the Pybricks BLE
`broadcast()` and `observe()` APIs to send data between hubs without
establishing a connection.

## Transport

Messages are sent as Bluetooth Low Energy Advertisement Data. This is detailed
in the Bluetooth [Core Specification] v4.0 or later.

[Core Specification]: https://www.bluetooth.com/specifications/specs/?types=specs-docs&keyword=core+specification&filter=

## Application

This describes how advertisements should be configured for sending data
(broadcasting) and how they should interpret the received data (observing).

As per the Bluetooth spec, all multi-byte numeric values are little-endian.

### Broadcasting

- Advertisements should be sent using a 100ms interval.
- Advertisements should be sent on all 3 radio channels.
- Advertisements should be sent using advertising data type of `ADV_NONCONN_IND` (undirected, not scannable, not connectable).
- Payload must contain only one advertisement data structure with type of Manufacturer Specific Data (0xFF).
- Manufacturer Specific Data must use LEGO company identifier (0x0397).

### Observing

- Should use passive scanning.
- Should scan on all 3 radio channels.
- Should use scan interval of 100ms.
- Should allow advertisement type other than `ADV_NONCONN_IND` (for City hub support).

### Data format

The data portion of the Manufacturer Specific Data is encoded as follows:

- First byte is the "channel" number (0 to 255).
- This is followed by 0 or more values encoded as follows:
  - A one byte header that indicates the type and size of the value.
    - Types are one of:
      - `SINGLE_OBJECT = 0`, Indicator that the next value is the one and only value (instead of a tuple).
      - `TRUE = 1`, the Python `True` value.
      - `FALSE = 2`, the Python `False` value.
      - `INT = 3`, the Python `int` type.
      - `FLOAT = 4`, the Python `float` type.
      - `STR = 5`, the Python `str` type.
      - `BYTES = 6`, the Python `bytes` type.
    - The length is the number of bytes that follow that contain the value:
      - For `SINGLE_OBJECT`, `TRUE`, and `FALSE`, the length is always 0.
      - For `INT`, the length is 1 if the value is an 8-bit signed int (-128 to
        127), 2 if the value is a 16-bit signed int (-32768 and 32767) or 4 if
        the value is a 32-bit signed int.
      - For `FLOAT` the length is always 4.
      - For `STR` and `BYTES`, the length can be 0 or greater.
    - The type and length are packed into one byte using `(type << 5) | (length & 0x1F)`.
  - The value encoding depends on the type.
    - `SINGLE_OBJECT`, `TRUE`, and `FALSE` have no value.
    - `INT` can be an 8-bit signed int, a 16-bit signed int or a 32-bit signed
      int depending on the given length.
    - `FLOAT` is a 32-bit IEEE 754 floating point value.
    - `STR` must be valid UTF-8 (without zero-termination).
    - `BYTES` has no restrictions.
  - Since advertisements payloads are limited to 31 bytes by the Bluetooth spec
    and there are 5 bytes of overhead, the combined size of all headers and
    values is limited to 26 bytes.

### Example payload

Tuple data:

```
0x0F, 0xFF, 0x97, 0x03, 0x01, 0x61, 0x64, 0x84, 0x00, 0x00, 0x80, 0x3f, 0xA2, 0x68, 0x69, 0x20
  ^     ^     ^     ^     ^     ^     ^     ^     ^     ^     ^     ^     ^     ^     ^     ^
  |     |     |_____|     |     |     |     |     |_____|_____|_____|     |     |_____|     |
  |     |     |           |     |     |     |     |                       |     |           Header indicating `TRUE` value.
  |     |     |           |     |     |     |     |                       |     `STR` value of "hi".
  |     |     |           |     |     |     |     |                       Header indicating `STR` value with length 2.
  |     |     |           |     |     |     |     `FLOAT` value of 1.0
  |     |     |           |     |     |     Header indicating `FLOAT` with length 4
  |     |     |           |     |     `INT` value of 100
  |     |     |           |     Header indicating `INT` with length 1
  |     |     |           Channel number
  |     |     LEGO Company Identifier
  |     Advertising data type indicating Manufacturer Data
  Length (number of bytes that follow, not including this one)
```

Single object:

```
0x07, 0xFF, 0x97, 0x03, 0x01, 0x00, 0x61, 0x64
  ^     ^     ^     ^     ^     ^     ^     ^
  |     |     |_____|     |     |     |     |
  |     |     |           |     |     |     |
  |     |     |           |     |     |     |
  |     |     |           |     |     |     |
  |     |     |           |     |     |     |
  |     |     |           |     |     |     `INT` value of 100
  |     |     |           |     |     Header indicating `INT` with length 1
  |     |     |           |     Header indicating `SINGLE_OBJECT`
  |     |     |           Channel number
  |     |     LEGO Company Identifier
  |     Advertising data type indicating Manufacturer Data
  Length (number of bytes that follow, not including this one)
```

## Additional resources

- [Reference implementation in Pybricks firmware](https://github.com/pybricks/pybricks-micropython/blob/fc0a89ba57fcd8d3e01aef807422e85f0abe6394/pybricks/common/pb_type_ble.c)
- [Video intro to BLE advertisements](https://www.bluetooth.com/bluetooth-resources/intro-to-bluetooth-advertisements)
- ["Everything you need to know" presentation slides](https://devzone.nordicsemi.com/cfs-file/__key/communityserver-discussions-components-files/4/6064.bluetoothLEAdvertisingPresentation.pdf)
