// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

#![allow(unused)]

// LiteX SoC Wishbone Register format
pub type SoCRegisterFmt = litex_vexriscv::litex_registers::LiteXSoCRegistersC32B32;

// constants defined in `generated/soc.h`

pub type ClockFrequency = kernel::hil::time::Freq1MHz;

pub const CONFIG_CPU_HAS_INTERRUPT: bool = true;
pub const CONFIG_CPU_RESET_ADDR: usize = 0;

pub const CONFIG_CPU_TYPE: &str = "vexriscv";
pub const CONFIG_CPU_VARIANT: &str = "secure";
pub const CONFIG_CPU_HUMAN_NAME: &str = "VexRiscv_Secure";
pub const CONFIG_CPU_NOP: &str = "nop";

pub const CONFIG_CSR_DATA_WIDTH: usize = 32;
pub const CONFIG_CSR_ALIGNMENT: usize = 32;
pub const CONFIG_BUS_STANDARD: &str = "WISHBONE";
pub const CONFIG_BUS_DATA_WIDTH: usize = 32;
pub const CONFIG_BUS_ADDRESS_WIDTH: usize = 32;

pub const ETHMAC_RX_SLOTS: usize = 2;
pub const ETHMAC_TX_SLOTS: usize = 2;
pub const ETHMAC_SLOT_SIZE: usize = 2048;

pub const GPIO_INTERRUPT: usize = 3;
pub const ETHMAC_INTERRUPT: usize = 2;
pub const TIMER0_INTERRUPT: usize = 1;
pub const UART_INTERRUPT: usize = 0;

// constants defined in `generated/csr.h`
pub const CSR_BASE: usize = 0xf0000000;
pub const CSR_CTRL_BASE: usize = CSR_BASE + 0x0000;
pub const CSR_ETHMAC_BASE: usize = CSR_BASE + 0x0800;
pub const CSR_ETHPHY_BASE: usize = CSR_BASE + 0x1000;
pub const CSR_GPIO_BASE: usize = CSR_BASE + 0x1800;
pub const CSR_IDENTIFIER_MEM_BASE: usize = CSR_BASE + 0x2000;
pub const CSR_TIMER0_BASE: usize = CSR_BASE + 0x2800;
pub const CSR_UART_BASE: usize = CSR_BASE + 0x3000;

// constants defined in `generated/mem.h`
pub const MEM_ETHMAC_BASE: usize = 0x80000000;
pub const MEM_ETHMAC_SIZE: usize = 0x00002000;
