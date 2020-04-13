Wireshark Dissectors
====================

[Wireshark][1] dissectors can be used to decode communication data (USB,
Bluetooth, Wi-Fi) into human-readable information.

[1]: https://www.wireshark.org/


Plugins
-------

- [LEGO MINDSTORMS EV3](/wireshark/ev3_dissector.lua)
- [LEGO Powered Up](/wireshark/lwp3_dissector.lua)


Usage
-----

This directory contains several plugins for [Wireshark][1] that can decode
LEGO communication protocols.

To add these to Wireshark:

1.  Open the *Help* menu and select *About Wireshark*.
2.  Go to the the *Folders* tab.
3.  Find the *Personal Lua Plugins* directory and open it.

    ![Screenshot of About Wireshark dialog](/wireshark/about_wireshark.png)

4. Copy one or more of the `.lua` files to this directory.
5. Open the *Analyze* menu and select *Reload Lua Plugins*.

Refer to Wireshark documentation for information on how to obtain communication
data to be analyzed.


