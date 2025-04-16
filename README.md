# USB Authentication

This repository is the home of the USB Authentication project.

USB authentication allows for a USB Host to authenticate a USB device.

The protocol is defined in:
- [Universal Serial Bus Security Specification, rev 1.0 with ECN 219](https://www.usb.org/document-library/usb-authentication-specification-rev-10-ecn-and-errata-through-january-7-2019)
- Universal Serial Bus Type-C Authentication Specification, rev 1.0 with ECN 2019

It concerns both Power Delivery devices and USB peripherals.

The project contains the following subprojects:

- Linux kernel host implementation and a userspace policy engine
- QEMU device implementation
- A tool to create a simple test PKI

The entirety of this work is released under the GPL-2.0 license.

## How to build?

### Dependencies

- virtme-ng
- podman
- make
- libnl-genl-3

### Makefile

The testbed Makefile defines three commands.

The `build` command builds a podman container embedding every dependencies to
compile Qemu, the Linux kernel and the demo policy engine. It builds a virtme-ng
micro-vm that can be executed with the `run` command.

The `test` commands runs the micro-vm and executes the policy engine to start
authentication of a qemu-emulated authenticated USB device.

If everything works as supposed, device authentication debug logs should appear
and end with the `device has been authorized` message. 

Since the authenticated emulated qemu device does not implement a fully working
device the following messages will then appear :

```
usbhid 1-1:1.0: can't add hid device: -32
usbhid 1-1:1.0: probe with driver usbhid failed with error -32
```

The test environment has been tested on Archlinux, Debian 12 and Fedora 42.
