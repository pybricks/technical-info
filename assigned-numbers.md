Assigned Numbers
================

Type IDs
--------

Type IDs are used to identify sensors and motors (including ones built into a
programmable brick).

| ID (hex) | Description |
|-|-|
| 0  (0x00) | _no device_ |
| 1  (0x01) | Powered Up Medium Motor |
| 2  (0x02) | Powered Up Train Motor |
| 8  (0x08) | Powered Up Lights |
| 20 (0x14) | Powered Up Hub battery voltage |
| 21 (0x15) | Powered Up Hub battery current |
| 22 (0x16) | Powered Up Hub piezo tone (WeDo 2.0 only) |
| 23 (0x17) | Powered Up Hub indicator light |
| 29 (0x1D) | EV3 Color Sensor |
| 30 (0x1E) | EV3 Ultrasonic Sensor |
| 32 (0x20) | EV3 Gyro Sensor |
| 33 (0x21) | EV3 Infrared Sensor |
| 34 (0x22) | WeDo 2.0 Tilt Sensor |
| 35 (0x23) | WeDo 2.0 Motion Sensor |
| 36 (0x24) | WeDo 2.0 generic device |
| 37 (0x25) | BOOST Color and Distance Sensor |
| 38 (0x26) | BOOST Interactive Motor |
| 39 (0x27) | BOOST Move Hub motor |
| 40 (0x28) | BOOST Move Hub accelerometer (tilt sensor) |
| 41 (0x29) | DUPLO Train hub motor |
| 42 (0x2a) | DUPLO Train hub beeper |
| 43 (0x2b) | DUPLO Train hub color sensor |
| 44 (0x2c) | DUPLO Train hub speed |   
| 46 (0x2e) | Technic Control+ Large Motor |
| 47 (0x2f) | Technic Control+ XL Motor |
| 48 (0x30) | SPIKE Prime Medium Motor |
| 49 (0x31) | SPIKE Prime Large Motor |
| 50 (0x32) | Technic Control+ Hub ? |
| 54 (0x36) | Powered Up hub IMU gesture |
| 55 (0x37) | Powered Up Handset Buttons |
| 56 (0x38) | Powered Up Handset Light? |
| 57 (0x39) | Powered Up hub IMU accelerometer |
| 58 (0x3A) | Powered Up hub IMU gyro |
| 59 (0x3B) | Powered Up hub IMU position |
| 60 (0x3C) | Powered Up hub IMU temperature |
| 61 (0x3D) | SPIKE Prime Color Sensor (45605) |
| 62 (0x3E) | SPIKE Prime Ultrasonic/Distance Sensor (45604) |
| 63 (0x3F) | SPIKE Prime Force Sensor (45606) |



Device IDs
----------

| ID (hex) | Description |
|-|-|
| 32 (0x20) | DUPLO Train Hub |
| 64 (0x40) | BOOST Move Hub |
| 65 (0x41) | Powered UP Smart Hub (Hub #4) |
| 66 (0x42) | Powered UP Handset (remote) |
| 128 (0x80) | TECHNIC Control+ Hub (Hub #2) |


Bluetooth
---------

### BLE UUIDs

LEGO-specific UUIDs:

| 16-bit | 128-bit | Description |
|-|-|-|
| 1523 | 00001523-1212-EFDE-1523-785FEABCD123 | WeDo 2.0 hub service |
| 1524 | 00001524-1212-EFDE-1523-785FEABCD123 | WeDo 2.0 name characteristic |
| 1526 | 00001526-1212-EFDE-1523-785FEABCD123 | WeDo 2.0 button state characteristic |
| 1527 | 00001527-1212-EFDE-1523-785FEABCD123 | WeDo 2.0 attached I/O characteristic |
| 1528 | 00001528-1212-EFDE-1523-785FEABCD123 | WeDo 2.0 low voltage alert characteristic |
| 152B | 0000152B-1212-EFDE-1523-785FEABCD123 | WeDo 2.0 disconnect characteristic |
| 1560 | 00001560-1212-EFDE-1523-785FEABCD123 | WeDo 2.0 input value characteristic |
| 1561 | 00001561-1212-EFDE-1523-785FEABCD123 | WeDo 2.0 input format characteristic |
| 1562 | 00001562-1212-EFDE-1523-785FEABCD123 | WeDo 2.0 input command characteristic |
| 1563 | 00001563-1212-EFDE-1523-785FEABCD123 | WeDo 2.0 output command characteristic |
| 4F0E | 00004F0E-1212-EFDE-1523-785FEABCD123 | WeDo 2.0 input service |
| 1623 | 00001623-1212-EFDE-1623-785FEABCD123 | Powered Up hub service |
| 1624 | 00001624-1212-EFDE-1623-785FEABCD123 | Powered Up hub characteristic |
| 1625 | 00001625-1212-EFDE-1623-785FEABCD123 | Powered Up bootloader service |
| 1626 | 00001626-1212-EFDE-1623-785FEABCD123 | Powered Up bootloader characteristic |


### BLE Advertising Data

Company ID: 919 (0x0397) - LEGO System A/S
