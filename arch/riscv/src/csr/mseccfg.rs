// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

use kernel::utilities::registers::register_bitfields;

// Default to 32 bit if compiling for debug/testing.
#[cfg(not(target_arch = "riscv64"))]
register_bitfields![usize,
    pub mseccfg [
        mml OFFSET(0) NUMBITS(1) [],
        mmwp OFFSET(1) NUMBITS(1) [],
        rlb OFFSET(2) NUMBITS(1) [],
    ]
];

#[cfg(not(target_arch = "riscv64"))]
register_bitfields![usize,
    pub mseccfgh [
        // This isn't a real entry, it just avoids compilation errors
        none OFFSET(0) NUMBITS(1) [],
    ]
];

#[cfg(target_arch = "riscv64")]
register_bitfields![usize,
    pub mseccfg [
        mml OFFSET(0) NUMBITS(1) [],
        mmwp OFFSET(1) NUMBITS(1) [],
        rlb OFFSET(2) NUMBITS(1) [],
    ]
];
