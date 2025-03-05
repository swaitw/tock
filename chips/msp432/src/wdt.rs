// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

//! Watchdog Timer (WDT)

use kernel::utilities::registers::interfaces::{ReadWriteable, Readable};
use kernel::utilities::registers::{register_bitfields, register_structs, ReadWrite};
use kernel::utilities::StaticRef;

const WATCHDOG_BASE: StaticRef<WdtRegisters> =
    unsafe { StaticRef::new(0x4000_4800u32 as *const WdtRegisters) };

// Every write access has to set this 'password' in the upper 8 bit of the
// register, otherwise the watchdog resets the whole system
const PASSWORD: u16 = 0x5A;

register_structs! {
    /// WDT_A
    WdtRegisters {
        (0x00 => _reserved0),
        /// Watchdog Timer Control Register
        (0x0C => ctl: ReadWrite<u16, WDTCTL::Register>),
        (0x0E => @END),
    }
}

register_bitfields![u16,
    WDTCTL [
        /// Watchdog timer interval select
        WDTIS OFFSET(0) NUMBITS(3) [
            /// Watchdog clock source / (2^(31)) (18:12:16 at 32.768 kHz)
            WatchdogClockSource231181216At32768KHz = 0,
            /// Watchdog clock source /(2^(27)) (01:08:16 at 32.768 kHz)
            WatchdogClockSource227010816At32768KHz = 1,
            /// Watchdog clock source /(2^(23)) (00:04:16 at 32.768 kHz)
            WatchdogClockSource223000416At32768KHz = 2,
            /// Watchdog clock source /(2^(19)) (00:00:16 at 32.768 kHz)
            WatchdogClockSource219000016At32768KHz = 3,
            /// Watchdog clock source /(2^(15)) (1 s at 32.768 kHz)
            WatchdogClockSource2151SAt32768KHz = 4,
            /// Watchdog clock source / (2^(13)) (250 ms at 32.768 kHz)
            WatchdogClockSource213250MsAt32768KHz = 5,
            /// Watchdog clock source / (2^(9)) (15.625 ms at 32.768 kHz)
            WatchdogClockSource2915625MsAt32768KHz = 6,
            /// Watchdog clock source / (2^(6)) (1.95 ms at 32.768 kHz)
            WatchdogClockSource26195MsAt32768KHz = 7
        ],
        /// Watchdog timer counter clear
        WDTCNTCL OFFSET(3) NUMBITS(1) [
            /// No action
            NoAction = 0,
            /// WDTCNT = 0000h
            WDTCNT0000h = 1
        ],
        /// Watchdog timer mode select
        WDTTMSEL OFFSET(4) NUMBITS(1) [
            /// Watchdog mode
            WatchdogMode = 0,
            /// Interval timer mode
            IntervalTimerMode = 1
        ],
        /// Watchdog timer clock source select
        WDTSSEL OFFSET(5) NUMBITS(2) [
            /// SMCLK
            SMCLK = 0,
            /// ACLK
            ACLK = 1,
            /// VLOCLK
            VLOCLK = 2,
            /// BCLK
            BCLK = 3
        ],
        /// Watchdog timer hold
        WDTHOLD OFFSET(7) NUMBITS(1) [
            /// Watchdog timer is not stopped
            WatchdogTimerIsNotStopped = 0,
            /// Watchdog timer is stopped
            WatchdogTimerIsStopped = 1
        ],
        /// Watchdog timer password
        WDTPW OFFSET(8) NUMBITS(8) []
    ]
];

pub struct Wdt {
    registers: StaticRef<WdtRegisters>,
}

impl Wdt {
    pub const fn new() -> Wdt {
        Wdt {
            registers: WATCHDOG_BASE,
        }
    }

    fn start(&self) {
        // Enable the watchdog and clear the counter
        self.registers
            .ctl
            .modify(WDTCTL::WDTPW.val(PASSWORD) + WDTCTL::WDTHOLD::CLEAR + WDTCTL::WDTCNTCL::SET);
    }

    pub fn disable(&self) {
        self.registers
            .ctl
            .modify(WDTCTL::WDTPW.val(PASSWORD) + WDTCTL::WDTHOLD::SET);
    }
}

impl kernel::platform::watchdog::WatchDog for Wdt {
    fn setup(&self) {
        // The clock-source of the watchdog is the SMCLK which runs at 1.5MHz. We configure a
        // prescaler of 2^15 which results in a watchdog interval of approximately 22ms ->
        // 2^15 / 1_500_000Hz = 32768 / 1_500_000 = 0.02184s

        // According to the datasheet p. 759 section 17.2.3 it's necessary to disable the watchdog
        // before setting it up and it's also necessary to set the WDTCNTCL bit within the same
        // write cycle where the config is applied in order to avoid unexpected interrupts and
        // resets.
        self.disable();
        // Set SMCLK as source -> 750kHz
        // Enable Watchdog mode
        // According to datasheet necessary
        // Prescaler of 2^15
        self.registers.ctl.modify(
            WDTCTL::WDTPW.val(PASSWORD)
                + WDTCTL::WDTSSEL::SMCLK
                + WDTCTL::WDTTMSEL::WatchdogMode
                + WDTCTL::WDTCNTCL::SET
                + WDTCTL::WDTIS::WatchdogClockSource2151SAt32768KHz,
        );

        self.start();
    }

    fn suspend(&self) {
        self.disable();
    }

    fn tickle(&self) {
        // If the watchdog was disabled (self.suspend()), start it again.
        if self.registers.ctl.is_set(WDTCTL::WDTHOLD) {
            self.start();
        } else {
            self.registers
                .ctl
                .modify(WDTCTL::WDTPW.val(PASSWORD) + WDTCTL::WDTCNTCL::SET);
        }
    }
}
