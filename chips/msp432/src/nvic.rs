// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

//! Nested Vector Interrupt Controller (NVIC)

pub const PSS: u32 = 0;
pub const CS: u32 = 1;
pub const PCM: u32 = 2;
pub const WDT_A: u32 = 3;
pub const FPU_INT: u32 = 4;
pub const FLCTL: u32 = 5;
pub const CMP_E0: u32 = 6;
pub const CMP_E1: u32 = 7;
pub const TIMER_A0_0: u32 = 8;
pub const TIMER_A0_1: u32 = 9;
pub const TIMER_A1_0: u32 = 10;
pub const TIMER_A1_1: u32 = 11;
pub const TIMER_A2_0: u32 = 12;
pub const TIMER_A2_1: u32 = 13;
pub const TIMER_A3_0: u32 = 14;
pub const TIMER_A3_1: u32 = 15;
pub const USCI_A0: u32 = 16;
pub const USCI_A1: u32 = 17;
pub const USCI_A2: u32 = 18;
pub const USCI_A3: u32 = 19;
pub const USCI_B0: u32 = 20;
pub const USCI_B1: u32 = 21;
pub const USCI_B2: u32 = 22;
pub const USCI_B3: u32 = 23;
pub const ADC: u32 = 24;
pub const TIMER32_INT1: u32 = 25;
pub const TIMER32_INT2: u32 = 26;
pub const TIMER32_COMBINED: u32 = 27;
pub const AES256: u32 = 28;
pub const RTC: u32 = 29;
pub const DMA_ERR: u32 = 30;
pub const DMA_INT3: u32 = 31;
pub const DMA_INT2: u32 = 32;
pub const DMA_INT1: u32 = 33;
pub const DMA_INT0: u32 = 34;
pub const IO_PORT1: u32 = 35;
pub const IO_PORT2: u32 = 36;
pub const IO_PORT3: u32 = 37;
pub const IO_PORT4: u32 = 38;
pub const IO_PORT5: u32 = 39;
pub const IO_PORT6: u32 = 40;
