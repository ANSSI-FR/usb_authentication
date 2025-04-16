#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
File name: main.py

Copyright: 2025, ANSSI
License: GPLv2

Author: Luc Bonnafoux, Nicolas Bouchinet
Created: 13/03/2025
Version: 0.1

Description: Main CLI for usb demonstration scripts

WARNING: this script is to be used only for demonstration purpose
"""

import argparse
import os
from pathlib import Path

import demo.generate_pki

def main():
  parser = argparse.ArgumentParser(
    prog='generate_pki',
    description='Utility functions to generate a simple PKI for the USB demonstration',
  )
  parser.add_argument(
    '-s', required=True, type=Path,
    help="Path to PKI directory"
  )
  parser.add_argument(
    '-p', '--pki', type=str,
    help='Generate a new PKI'
  )
  parser.add_argument(
    '-d', '--device', type=str,
    help='Add a new USB device in the PKI'
  )
  parser.add_argument(
    '--vid', type=str,
    help=(
      'Vendor ID, must be the same between intermediate CA and leaf certificates.'
      'Mandatory for devices, optional for intermediate certificates'
    )
  )
  parser.add_argument(
    '--pid', type=str,
    help=(
      'Product ID, must be the same between intermediate CA and leaf certificates.'
      'Mandatory for devices, optional for intermediate certificates'
    )
  )

  # Get parameters and sanitize them
  args = parser.parse_args()

  ## PKI directory, must exist and end with a trailing slash
  pki_dir = args.s

  if not os.path.exists(pki_dir) or not os.path.isdir(pki_dir):
    print("Invalid PKI directory")
    return

  pki_dir = os.path.join(pki_dir, '')

  ## Vendor ID, must be present to create a vendor
  ##  In order to perform rainy day tests, the value is checked but do not return
  vid = args.vid

  if args.device is not None and vid is None:
    print("VID is mandatory for device")

  ## Product ID, must be present to create a device
  ##  In order to perform rainy day tests, the value is checked but do not return
  pid = args.pid

  if args.device is not None and pid is None:
    print("PID is mandatory for device")

  # Run requested command
  if args.pki is not None:
    demo.generate_pki.generate_sign_key(pki_dir, "root")
    demo.generate_pki.generate_root_cert(pki_dir, "root", args.vid, args.pid)
    demo.generate_pki.generate_sign_key(pki_dir, "int")
    demo.generate_pki.generate_pki(pki_dir, args.pki, args.vid, args.pid)
  elif args.device is not None:
    demo.generate_pki.generate_sign_key(pki_dir, args.device)
    demo.generate_pki.generate_dev_cert(pki_dir, args.device, args.vid, args.pid)

if __name__=="__main__":
  main()