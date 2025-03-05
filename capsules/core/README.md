Core Tock Capsules
==================

This crate contains capsules which are required for most (if not all)
Tock-based systems to operate. For instance, these capsules implement
basic infrastructure for interacting with timer or alarm hardware,
exposing UART hardware as console ports, etc.

It further contains virtualizers, which enable a given single
peripheral to be used by multiple clients. Virtualizers are agnostic
over their underlying peripherals; they do not implement logic
specific to any given peripheral device.

For more information on capsules, see [the top-level README](../README.md).

The remainder of this document contains a list of capsules in this crate, along
with a short description.

MCU Peripherals for Userspace
-----------------------------

These capsules provide a `Driver` interface for common MCU peripherals.

- **[ADC](src/adc.rs)**: Individual and continuous samples.
- **[Alarm](src/alarm.rs)**: Oneshot and periodic timers.
- **[GPIO](src/gpio.rs)**: GPIO configuring and control.
- **[I2C_MASTER](src/i2c_master.rs)**: I2C master access only.
- **[I2C_MASTER_SLAVE](src/i2c_master_slave_combo.rs)**: I2C master and slave
  access.
- **[I2C_MASTER_SLAVE Driver](src/i2c_master_slave_driver.rs)**: I2C master and
  slave userspace access.
- **[RNG](src/rng.rs)**: Random number generation.
- **[SPI Controller](src/spi_controller.rs)**: SPI controller device (SPI
  master)
- **[SPI Peripheral](src/spi_peripheral.rs)**: SPI peripheral device (SPI slave)

Helpful Userspace Capsules
--------------------------

These provide common and better abstractions for userspace.

- **[Button](src/button.rs)**: Detect button presses.
- **[Console](src/console.rs)**: UART console support.
- **[Console Ordered](src/console_ordered.rs)**: UART console ordered with
  kernel `debug!()` prints.
- **[LED](src/led.rs)**: Turn on and off LEDs.

Debugging Capsules
------------------

These are selectively included on a board to help with testing and debugging
various elements of Tock.

- **[Low-Level Debug](src/low_level_debug)**: Provides system calls for
  low-level debugging tasks, such as debugging toolchain and relocation issues.
- **[Process Console](src/process_console.rs)**: Provide a UART console to
  inspect the status of process and stop/start them.

Virtualized Hardware Resources
------------------------------

These allow for multiple users of shared hardware resources in the kernel.

- **[Virtual ADC](src/virtualizers/virtual_adc.rs)**: Shared single ADC channel.
- **[Virtual AES-CCM](src/virtualizers/virtual_aes_ccm.rs)**: Shared AES-CCM engine.
- **[Virtual Alarm](src/virtualizers/virtual_alarm.rs)**: Shared alarm resource.
- **[Virtual Flash](src/virtualizers/virtual_flash.rs)**: Shared flash resource.
- **[Virtual I2C](src/virtualizers/virtual_i2c.rs)**: Shared I2C and fixed addresses.
- **[Virtual PWM](src/virtualizers/virtual_pwm.rs)**: Shared PWM hardware.
- **[Virtual RNG](src/virtualizers/virtual_rng.rs)**: Shared random number generator.
- **[Virtual SPI](src/virtualizers/virtual_spi.rs)**: Shared SPI and fixed chip select pins.
- **[Virtual Timer](src/virtualizers/virtual_timer.rs)**: Shared timer.
- **[Virtual UART](src/virtualizers/virtual_uart.rs)**: Shared UART bus.

Miscallenous Capsules & Infrastructure
--------------------------------------

These modules implement miscallenous functionality & infrastructure required by
other capsule crates or the wider Tock ecosystem.

- **[Driver Number Assignments](src/driver.rs)**: Global driver number
  assignments for userspace drivers.
- **[Stream](src/stream.rs)**: Macro-infrastructure for encoding and decoding
  byte-streams. Originally developed as part of the IEEE802.15.4 network stack.
