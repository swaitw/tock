// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

//! Named interrupts for the ESP32-C3 chip.
//! This matches what the HAL uses

#![allow(dead_code)]

pub const IRQ_WIFI_MAC: u32 = 0;
pub const IRQ_WIFI_NMI: u32 = 1;
pub const IRQ_WIFI_PWR: u32 = 2;
pub const IRQ_WIFI_BB: u32 = 3;
pub const IRQ_BT_MAC: u32 = 4;
pub const IRQ_BT_BB: u32 = 5;
pub const IRQ_BT_BB_NMI: u32 = 6;
pub const IRQ_RWBT: u32 = 7;
pub const IRQ_RWBLE: u32 = 8;
pub const IRQ_RWBT_NMI: u32 = 9;
pub const IRQ_RWBLE_NMI: u32 = 10;
pub const IRQ_I2C: u32 = 11;
pub const IRQ_SLC0: u32 = 12;
pub const IRQ_SLC1: u32 = 13;
pub const IRQ_APB_CTRL: u32 = 14;
pub const IRQ_UHCI0: u32 = 15;
pub const IRQ_GPIO: u32 = 16;
pub const IRQ_GPIO_NMI: u32 = 17;
pub const IRQ_SPI1: u32 = 18;
pub const IRQ_SPI2: u32 = 19;
pub const IRQ_I2S1: u32 = 20;
pub const IRQ_UART0: u32 = 21;
pub const IRQ_UART1: u32 = 22;
pub const IRQ_LEDC: u32 = 23;
pub const IRQ_EFUSE: u32 = 24;
pub const IRQ_CAN: u32 = 25;
pub const IRQ_USB: u32 = 26;
pub const IRQ_RTC_CORE: u32 = 27;
pub const IRQ_RMT: u32 = 28;
pub const IRQ_I2C_EXT0: u32 = 29;
pub const IRQ_TIMER1: u32 = 30;
pub const IRQ_TIMER2: u32 = 31;
pub const IRQ_TG0_T0_LEVEL: u32 = 32;
pub const IRQ_TG0_WDT_LEVEL: u32 = 33;
pub const IRQ_TG1_T0_LEVEL: u32 = 34;
pub const IRQ_TG1_WDT_LEVEL: u32 = 35;
pub const IRQ_CACHE_IA: u32 = 36;
pub const IRQ_SYSTIMER_TARGET0_EDGE: u32 = 37;
pub const IRQ_SYSTIMER_TARGET1_EDGE: u32 = 38;
pub const IRQ_SYSTIMER_TARGET2_EDGE: u32 = 39;
pub const IRQ_SPI_MEM_REJECT_CACHE: u32 = 40;
pub const IRQ_ICACHE_PRELOAD0: u32 = 41;
pub const IRQ_ICACHE_SYNC0: u32 = 42;
pub const IRQ_APB_ADC: u32 = 43;
pub const IRQ_DMA_CH0: u32 = 44;
pub const IRQ_DMA_CH1: u32 = 45;
pub const IRQ_DMA_CH2: u32 = 46;
pub const IRQ_RSA: u32 = 47;
pub const IRQ_AES: u32 = 48;
pub const IRQ_SHA: u32 = 49;
pub const IRQ_ETS_FROM_CPU_INTR0: u32 = 50;
pub const IRQ_ETS_FROM_CPU_INTR1: u32 = 51;
pub const IRQ_ETS_FROM_CPU_INTR2: u32 = 52;
pub const IRQ_ETS_FROM_CPU_INTR3: u32 = 53;
pub const IRQ_ETS_ASSIST_DEBUG: u32 = 54;
pub const IRQ_ETS_DMA_APBPERI_PMS: u32 = 55;
pub const IRQ_ETS_CORE0_IRAM0_PMS: u32 = 56;
pub const IRQ_ETS_CORE0_DRAM0_PMS: u32 = 57;
pub const IRQ_ETS_CORE0_PIF_PMS: u32 = 58;
pub const IRQ_ETS_CORE0_PIF_PMS_SIZE: u32 = 59;
pub const IRQ_ETS_BAK_PMS_VIOLATE: u32 = 60;
pub const IRQ_ETS_CACHE_CORE0_ACS: u32 = 61;
