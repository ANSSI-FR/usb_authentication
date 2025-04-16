#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
File name: usb_if_acd.py

Copyright: 2025, ANSSI
License: GPLv2

Author: Luc Bonnafoux, Nicolas Bouchinet
Created: 12/03/2025
Version: 0.1

Description: Definition of the USB-IF ACD extension as defined in :
              - USB Type-C Authentication Specification, Rev 1.0 with ECN and Errata through January 7, 2019
            It builds on the class `cryptography.x509.UnrecognizedExtension`

WARNING: this script is to be used only for demonstration purpose

Dependencies: cryptography
"""

from enum import IntEnum
from cryptography import x509

class TlvType(IntEnum):
  """TLV Types as defined in Table A-2"""
  VERSION                     = 0x00
  XID                         = 0x01
  POWER_SOURCE_CAPABILITIES   = 0x02
  POWER_SOURCE_CERTIFICATIONS = 0x03
  CABLE_CAPABILITIES          = 0x04
  SECURITY_DESCRIPTION        = 0x05
  PLAYPEN                     = 0xFD
  VENDOR_EXTENSION            = 0xFE
  EXTENSTION                  = 0xFF

  @property
  def value(self):
    return self._value_.to_bytes(1, 'big')

class TlvField():
  """Generic class for TLV structures"""
  def __init__(self, type: TlvType):
    self._type = type
    self._value = bytearray()

  @property
  def tlv_type(self) -> int:
    return int.from_bytes(self._type.value, 'big')

  @property
  def value(self) -> bytes:
    return self._value

class VersionTlv(TlvField):
  """Version TLV as defined in §A.1.1"""
  def __init__(self):
    super().__init__(TlvType.VERSION)
    self._value.append(TlvType.VERSION) # Type: VERSION
    self._value += b'\x02' # Length: 2
    self._value += b'\x80\x00' # Version: USB device

class XidTlv(TlvField):
  """XID TLV as defined in §A.1.2"""
  def __init__(self, value: bytes):
    super().__init__(TlvType.XID)
    self._value.append(TlvType.XID) # Type : XID
    self._value += b'\x04' # Length: 4
    self._value += value[:4] # XID value on 4 bytes

class SecurityTlv(TlvField):
  """Security TLV as defined in §A.1.6"""
  def __init__(self, fips: bytes, cc: bytes, sec: bytes, vendor: bytes):
    super().__init__(TlvType.SECURITY_DESCRIPTION)
    self._value.append(TlvType.SECURITY_DESCRIPTION)
    self._value += b'\x06'
    self._value += fips
    self._value += cc
    self._value += sec
    self._value += vendor

class PlaypenTlv(TlvField):
  """Playpen TLV as defined in §A.1.7"""
  def __init__(self, value: bytes, length: int):
    super().__init__(TlvType.PLAYPEN)
    self._value.append(TlvType.PLAYPEN)
    self._value += length.to_bytes(1, 'big')
    self._value += value[:length]

class VendorTlv(TlvField):
  """Vendor Extension TLV as defined in §A.1.8"""
  def __init__(self, value: bytes, length: int):
    super().__init__(TlvType.VENDOR_EXTENSION)
    self._value.append(TlvType.VENDOR_EXTENSION)
    self._value += length.to_bytes(1, 'big')
    self._value += value[:length]

class ExtensionTlv(TlvField):
  """Extension TLV as defined in §A.1.9"""
  def __init__(self, value: bytes, length: int):
    super().__init__(TlvType.EXTENSTION)
    self._value.append(TlvType.EXTENSTION)
    self._value += length.to_bytes(1, 'big')
    self._value += value[:length]

class UsbIfAcd(x509.UnrecognizedExtension):
  """USB-IF ACD extension as defined in §3.1.3.6

  Raises
  ------
    TypeError
  """
  def __init__(self):
    super().__init__(x509.ObjectIdentifier('2.23.145.1.1'), bytes())
    self._tlvs = []

  def add_tlv(self, tlv: TlvField):
    if not isinstance(tlv, TlvField):
      raise TypeError("tlv must be one of the TlvField subclass")

    self._tlvs.append(tlv)

    # Rebuild value
    tlv_list = sorted(self._tlvs, key=lambda x: x.tlv_type)

    self._value = bytearray()
    for tlv in tlv_list:
      self._value += tlv.value