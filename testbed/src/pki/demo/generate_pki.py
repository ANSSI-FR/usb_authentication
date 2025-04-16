#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
File name: generate_pki.py

Copyright: 2025, ANSSI
License: GPLv2

Author: Luc Bonnafoux, Nicolas Bouchinet
Created: 12/03/2025
Version: 0.1

Description: This script provides utility functions to generate the PKI used for
            USB authentication demonstration. It provides the following functions:
              - generate PKI from scratch
              - generate device signing key pair

WARNING: this script is to be used only for demonstration purpose

Dependencies: cryptography
"""

import datetime
import os
import base64
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID
from cryptography import x509
from cryptography import exceptions

from .usb_if_acd import UsbIfAcd, VersionTlv, SecurityTlv

# PKI constants
COUNTRY_NAME = "FR"
STATE_OR_PROVINCE_NAME = "France"
LOCALITY_NAME = "Paris"

ROOT_CERT = "root_cert.pem"
ROOT_KEY  = "root_key.pem"
INT_CERT  = "int_cert.pem"
INT_KEY   = "int_key.pem"

def generate_root_cert(pki_dir: Path, name: str, vid: str, pid: str):
  """Generate a root CA certificate

  Parameters
  ----------
  pki_dir : Path
    Directory in which the PKI will be created, must be terminated by a "\"
  name: str
    Name of the PKI, will appear in ORGANIZATION_NAME of both the root and intermediate
  vid: str
    Vendor ID, if not None will appear in the COMMON_NAME of both the root and intermediate
  pid: str
    Product ID, if not None will appear in the COMMON_NAME of both the root and intermediate
  """

  # Create COMMON_NAME according to [USB Type-C Authentication Specification] §3.1.3.1.1
  common_name = 'USB:'
  if vid is not None:
    common_name += vid
  common_name += ':'
  if pid is not None:
    common_name += pid

  # Load CA root key
  with open(pki_dir + ROOT_KEY, 'rb') as data:
    root_key = serialization.load_pem_private_key(data.read(), password=None)

  # Save root key to disk
  with open(pki_dir + ROOT_KEY, "wb") as f:
    f.write(root_key.private_bytes(
      encoding=serialization.Encoding.PEM,
      format=serialization.PrivateFormat.TraditionalOpenSSL,
      encryption_algorithm=serialization.NoEncryption(),
    ))

  # Generate CA root certicate
  subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, name),
    x509.NameAttribute(NameOID.COMMON_NAME, common_name),
  ])

  root_cert = x509.CertificateBuilder().serial_number(
            x509.random_serial_number()
          ).issuer_name(
            issuer
          ).not_valid_before(
            datetime.datetime.strptime('19700101000000Z','%Y%m%d%H%M%SZ')
          ).not_valid_after(
            datetime.datetime.strptime('99991231235959Z','%Y%m%d%H%M%SZ')
          ).subject_name(
            subject
          ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()),
            critical=False,
          ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True
          ).add_extension(
            x509.KeyUsage(
              digital_signature=False,
              content_commitment=False,
              key_encipherment=False,
              data_encipherment=False,
              key_agreement=False,
              key_cert_sign=True,
              crl_sign=True,
              encipher_only=False,
              decipher_only=False
            ),
            critical=True,
          ).add_extension(
            x509.ExtendedKeyUsage(
              [x509.ObjectIdentifier('2.23.145.1.1')] # USB-IF OID as defined in §3.1.3.4
            ),
            critical=True,
          ).public_key(
            root_key.public_key()
          ).sign(root_key, hashes.SHA256())

  # Save root certificate to disk
  with open(pki_dir+ROOT_CERT, "wb") as f:
    f.write(root_cert.public_bytes(serialization.Encoding.PEM))

def generate_pki(pki_dir: Path, name: str, vid: str, pid: str):
  """Generate an intermediate CA certificate

  Parameters
  ----------
  pki_dir : Path
    Directory in which the PKI will be created, must be terminated by a "\"
  name: str
    Name of the PKI, will appear in ORGANIZATION_NAME of both the root and intermediate
  vid: str
    Vendor ID, if not None will appear in the COMMON_NAME of both the root and intermediate
  pid: str
    Product ID, if not None will appear in the COMMON_NAME of both the root and intermediate
  """

  # Create COMMON_NAME according to [USB Type-C Authentication Specification] §3.1.3.1.1
  common_name = 'USB:'
  if vid is not None:
    common_name += vid
  common_name += ':'
  if pid is not None:
    common_name += pid

  # Load CA root key
  with open(pki_dir + ROOT_KEY, 'rb') as data:
    root_key = serialization.load_pem_private_key(data.read(), password=None)

  # Load root CA certificate
  with open(pki_dir + ROOT_CERT, 'rb') as data:
    root_cert = x509.load_pem_x509_certificate(data.read())

  # Load CA intermediate key
  with open(pki_dir+"int_key.pem", 'rb') as data:
    int_key = serialization.load_pem_private_key(data.read(), password=None)

  # Generate CA intermediate certicate
  subject = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, COUNTRY_NAME),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, STATE_OR_PROVINCE_NAME),
    x509.NameAttribute(NameOID.LOCALITY_NAME, LOCALITY_NAME),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, name),
    x509.NameAttribute(NameOID.COMMON_NAME, common_name),
  ])

  int_cert = x509.CertificateBuilder().subject_name(
          subject
          ).issuer_name(
            root_cert.subject
          ).public_key(
            int_key.public_key()
          ).serial_number(
            x509.random_serial_number()
          ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
          ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365*10)
          ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True
          ).add_extension(
            x509.KeyUsage(
              digital_signature=False,
              content_commitment=False,
              key_encipherment=False,
              data_encipherment=False,
              key_agreement=False,
              key_cert_sign=True,
              crl_sign=True,
              encipher_only=False,
              decipher_only=False
            ),
            critical=True,
          ).add_extension(
            x509.ExtendedKeyUsage(
              [x509.ObjectIdentifier('2.23.145.1.1')] # USB-IF OID as defined in §3.1.3.4
            ),
            critical=True,
          ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(int_key.public_key()),
            critical=False,
          ).add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
              root_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
            ),
            critical=False,
          ).sign(root_key, hashes.SHA256())

  # Save intermediate certificate to disk
  with open(pki_dir+INT_CERT, "wb") as f:
    f.write(int_cert.public_bytes(serialization.Encoding.PEM))

"""
  QEMU configuration file template
"""
qemu_conf_tmp = """
{{
"slots": [
    {{
      "slot": 0,
      "key": "{dev_priv_key}",
      "cert": "{dev_cert_chain}"
    }}
  ]
}}"""

def generate_dev_cert(pki_dir: Path, name: str, vid: str, pid: str):
  """Generate a new private signing key for a device and enroll it in the PKI

  Outputs
  -------
  Private signature key in unencrypted PEM file
  Public certificate in PEM file and DER file
  Public certificate chain in DER file and base64 file, conform to USB spec.
    - Length       : 2 B
    - Reserved     : 2 B
    - RootHash     : 32 B
    - Certificates : Length - 36 B

  Parameters
  ----------
  pki_dir : str
    Directory in which the PKI will be created, must be terminated by a "\"
  name : str
    Name of the new USB device
  """

  # Create COMMON_NAME according to [USB Type-C Authentication Specification] §3.1.3.1.1
  common_name = 'USB:'
  if vid is not None:
    common_name += vid
  common_name += ':'
  if pid is not None:
    common_name += pid

  # Load root CA certificate
  with open(os.path.join(pki_dir,ROOT_CERT), 'rb') as data:
    root_cert = x509.load_pem_x509_certificate(data.read())

  # Load intermediate CA signing key and certificate
  with open(os.path.join(pki_dir,INT_KEY), 'rb') as data:
    int_key = serialization.load_pem_private_key(data.read(), password=None)

  with open(os.path.join(pki_dir,INT_CERT), 'rb') as data:
    int_cert = x509.load_pem_x509_certificate(data.read())

  # Load device signing key
  with open(os.path.join(pki_dir, name+"_key.pem"), 'rb') as data:
    dev_key = serialization.load_pem_private_key(data.read(), password=None)

  # Generate device certicate
  subject = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, COUNTRY_NAME),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, STATE_OR_PROVINCE_NAME),
    x509.NameAttribute(NameOID.LOCALITY_NAME, LOCALITY_NAME),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, name),
    x509.NameAttribute(NameOID.COMMON_NAME, common_name),
  ])

  usb_ext = UsbIfAcd()
  usb_ext.add_tlv(VersionTlv())
  usb_ext.add_tlv(SecurityTlv(b'\x01', b'\x02\x03', b'\x04', b'\x05\x06'))

  dev_cert = x509.CertificateBuilder().subject_name(
          subject
          ).issuer_name(
            int_cert.subject
          ).public_key(
            dev_key.public_key()
          ).serial_number(
            x509.random_serial_number()
          ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
          ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365*10)
          ).add_extension(
            x509.SubjectAlternativeName([
              x509.DNSName(name)
            ]),
            critical=False,
          ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
          ).add_extension(
            x509.KeyUsage(
              digital_signature=True,
              content_commitment=False,
              key_encipherment=False,
              data_encipherment=False,
              key_agreement=False,
              key_cert_sign=False,
              crl_sign=False,
              encipher_only=False,
              decipher_only=False
            ),
            critical=True,
          ).add_extension(
            x509.ExtendedKeyUsage(
              [x509.ObjectIdentifier('2.23.145.1.1')] # USB-IF OID as defined in §3.1.3.4
            ),
            critical=True,
          ).add_extension(
            usb_ext,
            critical=True,
          ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(dev_key.public_key()),
            critical=False,
          ).add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
              int_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
            ),
            critical=False,
          ).sign(int_key, hashes.SHA256())

  # Save device certificate to disk
  with open(os.path.join(pki_dir,name+"_cert.pem"), "wb") as f:
    f.write(dev_cert.public_bytes(serialization.Encoding.PEM))

  with open(os.path.join(pki_dir,name+"_cert.der"), "wb") as f:
    f.write(dev_cert.public_bytes(serialization.Encoding.DER))

  # Create certificate chain, format defined in Table 3-1
  chain = bytearray()

  digest = hashes.Hash(hashes.SHA256())
  digest.update(root_cert.public_bytes(serialization.Encoding.DER))

  chain += digest.finalize()

  chain += int_cert.public_bytes(serialization.Encoding.DER)
  chain += dev_cert.public_bytes(serialization.Encoding.DER)

  length = bytearray()
  length += (len(chain)+4).to_bytes(2, 'little')
  length += b'\x00\x00'

  chain = length + chain

  with open(os.path.join(pki_dir,name+"_chain.der"), "wb") as f:
    f.write(chain)

  chain_b64 = base64.b64encode(chain)
  with open(os.path.join(pki_dir, name+"_chain.b64"), "wb") as f:
    f.write(chain_b64)

  # Generate QEMU configuration file
  with open(os.path.join(pki_dir, name+"_dev_config.json"), "w") as f:
    prv_key = dev_key.private_bytes(
      encoding=serialization.Encoding.PEM,
      format=serialization.PrivateFormat.TraditionalOpenSSL,
      encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8").replace("\n","\\n")

    chain_b64 = chain_b64.decode("utf-8")

    f.write(qemu_conf_tmp.format(
        dev_priv_key = prv_key,
        dev_cert_chain = chain_b64
      ))

def generate_sign_key(pki_dir: Path, name: str):
  """Generate a private signing key

  Parameters
  ----------
    pki_dir - Path to the PKI directory
    name    - Name of the key
  """

  key = ec.generate_private_key(ec.SECP256R1())

  pub_key = key.public_key()

  # Test signature
  message = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12'

  signature = key.sign(message, ec.ECDSA(hashes.SHA256()))

  try:
    pub_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
  except exceptions.InvalidSignature:
    print ("Invalid signature")

  # Save device key to disk
  with open(os.path.join(pki_dir,name+"_key.pem"), "wb") as f:
    f.write(key.private_bytes(
      encoding=serialization.Encoding.PEM,
      format=serialization.PrivateFormat.TraditionalOpenSSL,
      encryption_algorithm=serialization.NoEncryption(),
    ))
