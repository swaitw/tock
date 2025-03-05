LiteX SoC on the Digilent Arty-A7 FPGA Board
============================================

This board is targeting a SoC bitstream built using
[LiteX](https://github.com/enjoy-digital/litex), for the [Digilent
Arty-A7 FPGA
board](https://reference.digilentinc.com/reference/programmable-logic/arty-a7/start).

Since LiteX is a SoC builder, the individual generated bitstreams can
differ significantly depending on the LiteX release and configuration
options used. This board definition currently targets and has been
tested with
- [the LiteX SoC generator, revision
  a6d9955c9d3065](https://github.com/enjoy-digital/litex/tree/a6d9955c9d3065)
- using the companion [target
  file](https://github.com/litex-hub/litex-boards/blob/52f9f0f1079085/litex_boards/targets/digilent_arty.py)
  from `litex-boards`
- built around a VexRiscv-CPU with PMP, hardware multiplication and
  compressed instruction support (named `TockSecureIMC`)
- along with the following configuration options:

  ```
  --uart-baudrate=1000000
  --cpu-variant=tock+secure+imc
  --csr-data-width=32
  --timer-uptime
  --integrated-rom-size=0xb000
  --with-ethernet
  --with-buttons
  --with-xadc
  --with-dna
  --with-spi-flash
  ```

The `tock+secure+imc` is a custom VexRiscv CPU variant, based on the
build infrastructure in
[pythondata-cpu-vexriscv](https://github.com/litex-hub/pythondata-cpu-vexriscv),
which is patched to introduce a CPU with physical memory protection,
hardware multiplication and compressed instruction support (such that
it is compatible with the `rv32imc` arch).

Prebuilt and tested bitstreams (including the generated VexRiscv CPU
Verilog files and a patched LiteX version to support them) can be
obtained from the [Tock on LiteX companion repository
releases](https://github.com/lschuermann/tock-litex/releases/). The
current board definition has been verified to work with [release
2024011101](https://github.com/lschuermann/tock-litex/releases/tag/2024011101).
The bitstream for this board is located in `digilent_arty_a7-35t.zip`
or `digilent_arty_a7-100t.zip` under `gateware/digilent_arty.bit`.

Many bitstream customizations can be represented in the Tock board by
simply changing the variables in
`src/litex_generated_constants.rs`. To support a different set of FPGA
cores and perform further modifications, the `src/main.rs` file will
have to be modified.


Please note
-----------

This board is still in development. The following on-board components
and cores are supported:
- [X] Timer (with uptime support)
- [X] UART output via USB-FTDI
- [X] Green onboard LEDs
- [X] 100MBit/s Ethernet MAC
- [X] GPIO Interface
- [X] Buttons and Switches

The following components and cores require porting:
- [ ] RGB LEDs
- [ ] XADC Core
- [ ] FPGA DNA Core
- [ ] SPI Flash


Building the SoC / Programming the FPGA
---------------------------------------

The [Tock on LiteX companion
repository](https://github.com/lschuermann/tock-litex) contains instructions for
how to build the specific FPGA bitstream as targeted with this board
definition. Please refer to the [LiteX
documentation](https://github.com/enjoy-digital/litex/wiki/) for general
instructions on how to install and use the LiteX SoC generator.

Once LiteX and Xilinx Vivado is installed, building a bitstream should
be as simple as:

```
$ cd $PATH_TO_LITEX_BOARDS/litex_boards/targets
$ ./digilent_arty.py <configuration options> --build
```

This will produce a folder `build/digilent_arty/gateware` containing
the generated bitstream for the FPGA (`arty.bin`).

In addition to that, a folder `build/digilent_arty/software` will be
included containing support code and the SoC bios stored in ROM. The
individual SoC configuration options, interrupt assignments, register
(LiteX configuration status registers) addresses, etc. relevant for
Tock can be found in
`build/digilent_arty/software/include/generated/{csr.h,regions.ld,soc.h}`.

The bitstream can be programmed either by using Xilinx Vivado or running:

```
$ ./digilent_arty.py <configuration options> --load
```

To persistently write the bitstream to the included SPI flash, use the
Xilinx Vivado tools as outlined in [this
manual](https://reference.digilentinc.com/learn/programmable-logic/tutorials/arty-programming-guide/start#programming_the_arty_using_quad_spi). The
SPI flash used on the board may deviate from the manual, the part
number to select in Xilinx Vivado will be written on the SPI flash
chip.


Programming
-----------

By default, the LiteX SoC will feature an integrated BIOS in ROM,
which acts as a bootloader. The Tock kernel binary can be loaded
either using `litex_term.py` (sometimes available as `lxterm`) via
serial, or using TFTP via Ethernet. The uploaded image will be placed
into the `main_ram` section and executed.

### Serial boot

To boot via serial run the LiteX-included `litex_term.py` (sometimes
available as `lxterm`):
```
$ ./litex/litex/tools/litex_term.py \
    --speed 1000000 \
    --serial-boot \
    --kernel $TOCK_BINARY \
    $SERIAL_PORT
```
, where `TOCK_BINARY` points to the board's binary (kernel, optionally
including optionally applications), and `SERIAL_PORT` is the UART
console on which the bootloader listens (e.g. `/dev/ttyUSB0`).

Then press RESET to get the SoC into the bootloader stage:
```
        __   _ __      _  __
       / /  (_) /____ | |/_/
      / /__/ / __/ -_)>  <
     /____/_/\__/\__/_/|_|
   Build your hardware, easily!

 (c) Copyright 2012-2020 Enjoy-Digital
 (c) Copyright 2007-2015 M-Labs

 BIOS built on Jan  1 1970 00:00:01
 BIOS CRC passed (00000000)

[...]

 --============== Boot ==================--
Booting from serial...
Press Q or ESC to abort boot completely.
sL5DdSMmkekro
```

The `litex_term.py` script should recognize this string and initiate
the serial boot afterwards.

If everything works you should be greeted by the Tock kernel:
```
[LXTERM] Done.
Executing booted program at 0x40000000

--============= Liftoff! ===============--
LiteX+VexRiscv on ArtyA7: initialization complete, entering main loop.
```

### TFTP Boot

If applications are inserted into the Tock image, it can grow to a
significant size which makes upload via serial slow. Using TFTP is
preferable.

To make a binary bootable via TFTP, assign the PC the address
`192.168.1.100/24` on the desired interface and make the kernel image
available as `boot.bin` on your TFTP server:

```
$ cp $PATH_TO_TOCK/target/riscv32i-unknown-none-elf/release/litex_arty.bin \
    /srv/tftp/boot.bin
```

Make sure that the tftp server is running and the firewall is
configured correctly.

### Running Applications

The LiteX Arty board does not currently expose or use any persistent storage,
other than to hold the FPGA bistream containing the LiteX BIOS. For this reason,
Tockloader is not able to interact with this board directly. However, Tockloader
includes a flash-file support mode which supports operating on a binary file
representing the device's flash. This can be used to combine the kernel and
applications in a single binary, which can then be loaded onto the board using
the above methods. An example of this is illustrated below:

```
$ tockloader flash \
    --board litex_arty \
    --flash-file ./litex_arty_flash.bin \
    -a 0x0 \
    ./tock/target/riscv32imc-unknown-none-elf/release/litex_arty.bin
[INFO   ] Operating on flash file "./litex_arty_flash.bin".
[INFO   ] Limiting flash size to 0x8000000 bytes.
[STATUS ] Flashing binary to board...
[INFO   ] Finished in 0.000 seconds
$ tockloader install \
    --board litex_arty \
    --arch rv32imc \
    --flash-file ./litex_arty_flash.bin \
    ./libtock-c/examples/c_hello/build/c_hello.tab
[INFO   ] Using settings from KNOWN_BOARDS["litex_arty"]
[INFO   ] Operating on flash file "./litex_arty_flash.bin".
[INFO   ] Limiting flash size to 0x10000000 bytes.
[STATUS ] Installing app on the board...
[INFO   ] Found sort order:
[INFO   ]   App "c_hello" at address 0x41000060
[INFO   ] Finished in 0.002 seconds
```

Debugging
---------

LiteX makes it easy to generate vastly different SoCs. Prior to
creating an issue on GitHub, please verify that all variables in
`src/litex_generated_constants.rs` correspond to the values provided to LiteX or
generated by it. The respective file paths for the source of each
value is included as a comment.

It is possible to extend the VexRiscv-CPU with a debug port, which is
exposed on the Wishbone bus of the SoC. This can then be used to
attach a GDB debugger via the Network using the Etherbone
(`--with-etherbone`) core. For more information refer to the LiteX
documentation and [this quickstart
guide](https://github.com/timvideos/litex-buildenv/wiki/Debugging).
