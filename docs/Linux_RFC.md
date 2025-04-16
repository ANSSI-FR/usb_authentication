# USB peripheral authentication

USB peripherals are an important attack vector in personal computers
and pose a risk to the cyber security of companies and organizations.

The USB foundation has published a standard to allow the authentication
of USB peripherals ([1] and [2]). It defines a mechanism for the host to request credentials and
issue an authentication challenge to USB-2 or USB-3 peripherals, either upon connection
or later during the use of the peripheral.

We currently envision the following use cases for USB authentication:

- company networks where computers and peripherals can be privately controlled
and administered;
- USB cleaning or decontamination stations;
- individuals who want to prevent unauthorized device plug-in into their machine.

The implementation of this feature will obviously necessitate efforts from both
the kernel community and peripherals vendors. We believe that providing an
implementation of the host side of the protocol in the Linux kernel will
encourage constructors to include this feature in their devices. On the other hand, we are
working on implementing reference code for embedded devices, notably for
Zephyr OS.

## Design

The USB authentication protocol is based on a
simple signature challenge. Devices hold between 1 and 8 pairs of private
signing key and x509 certificate. Hosts must possess a store of root
Certificate Authority certificates provided by device vendors.

The protocol exchange is driven by the host and can be decomposed into three,
mostly independent, phases:

- The Host can request a digest of each certificate owned by the peripheral.
- If the Host does not recognize the peripheral from one of its digests, it can
read one or more certificates from the device until a valid one is found.
- The Host can issue an authentication challenge to the peripheral.

On the host side, this requires the following functions:

- handling the protocol exchange with the peripheral;
- X509 certificates validation and administration (root CA loading, certificate
revocation…);
- cryptographic functions for the challenge (random number generation and ECDSA
with the NIST P256 -secp256r1- curve);
- security policy management;
- authorization decision enforcement.

We chose to implement the authentication protocol exchange directly in the
kernel USB stack during the device enumeration. This is done by first requesting
the device BOS to detect its capacity at handling authentication, then if supported
starting the authentication sequence with a digest request.

The implementation of the other functions is open to several design alternatives, mainly
based on their distribution between kernel and user space. In this
first implementation, we chose to implement most (all) of the cryptographic
functions, certificate management and security policy management in user space
in order to limit impact on the kernel side. This allows for more personalization
later on. The communication between the kernel USB stack authentication function
and user space is done via a generic netlink socket.

The authorization decision enforcement can be done via the authorized field of
the usb_device and the associated authorization and deauthorization functions.
The usb_device also contains an authenticated field that could be used to track
the result of the authentication process and allow for more complex security
policy: the user could manually authorize a device that failed the
authentication, or manually deauthorize a device that was previously
authenticated.

## Limitations

The USB authentication protocol come with some inherent limitations, [3] does a
good job at describing most of them. During the implementation, we also found
that the value encoding of the Validity field in the x509 certificate differs
from the RFC5280 [4]. This has prevented us from using the x509 parser included in
the Linux kernel or OpenSSL, we chose to use the mbedtls library instead [5].
This obviously does not prevent others to replace it with their preferred
implementation. It will also open discussions on the protocol enhancement.

The architectural choice to place most of the cryptographic and security
management functions in user space comes with its own limitations.

First it introduces a dependency on the user space program availability. It will
probably be necessary to introduce a fail-safe mechanism if the authentication can
not be completed. Also, during early boot stages the user space service will be
needed in one form or another in the initramfs.

The second limitation is that the device initialization process is paused
multiple times. Each time, the hub lock is released in order not to block the
rest of the stack; and then reacquired when a response has been received from
user space. The resuming of the operation on the device must be done with great
care.

Last, we do not yet interface properly with the rest of the usb stack and thus
do not enforce a strict control of the two authenticated and authorized fields.
Other sections of the kernel or userspace are able to overwrite those fields
using the sysfs exposed files for example.

## Status

The current kernel implementation of the USB authentication protocol is
experimental and has the following limitations:

- It does not yet handle all possible protocol errors.
- It has been tested with a QEMU mock device, but tests with real hardware are
still in progress. As such, the over-the-wire protocol has not yet been fully
validated.
- The kernel/user space communication has not yet been completely validated,
including the interruption of the worker thread and its resuming.
- Device authorization and deauthorization has not been completely implemented.
- It lacks an overall documentation and test suite.

## Upstreaming plans

Our current kernel patch is obviously a work-in-progress and not yet ready for
merging. We feel it is best to start a discussion on the architectural choices
and gather early comments that could be used to improve the design.

Concerning the user space functions, they are currently implemented in a small
independent executable as a proof-of-concept. In the future,
integrating it in existing larger projects, like USBGuard [6], would allow
presenting a homogeneous USB administration interface to the user.

## Reviewing this RFC

We would like to get comments on the proposed architectural choices regarding
the repartition of functions between kernel and user space and on the
implementation in the USB stack, mostly concerning the releasing and reacquiring
the hub lock multiple times during the authentication process.

## Testing this RFC

You can find in the following repository [7] the necessary code for creating a
test environment:

- the Linux kernel patches;
- a python utility to generate a small PKI for device enrollment;
- a C minimalist service to implement the USB policy engine;
- patches for QEMU to implement a mock USB device with the authentication
capability;
- a testbed to compile and test the project.

## References

- [1] “Universal Serial Bus Security Foundation Specification”, Revision 1.0 with
ECN and Errata through January 7, 2019
- [2] “Universal Serial Bus Type-C Authentication Specification”, Revision 1.0
with ECN and Errata through January 7, 2019
- [3] J. Tian, N. Scaife, D. Kumar, M. Bailey, A. Bates and K. Butler, "SoK: "Plug
& Pray" Today – Understanding USB Insecurity in Versions 1 Through C," 2018 IEEE
Symposium on Security and Privacy (SP), San Francisco, CA, USA, 2018, pp.
1032-1047, doi: 10.1109/SP.2018.00037
- [4] RFC 5280, Internet X.509 Public Key Infrastructure Certificate and
Certificate Revocation List (CRL) Profile, May 2008
- [5] https://www.trustedfirmware.org/projects/mbed-tls/
- [6] https://usbguard.github.io/
- [7] https://github.com/ANSSI-FR/usb_authentication
