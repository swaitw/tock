#!/bin/bash

# Licensed under the Apache License, Version 2.0 or the MIT License.
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright Tock Contributors 2023.

esptool.py --port /dev/ttyUSB0 --chip esp32c3 elf2image --use_segments --output binary.hex ${1}
esptool.py --port /dev/ttyUSB0 --chip esp32c3 write_flash --flash_mode dio --flash_size detect --flash_freq 80m  0x0 binary.hex
