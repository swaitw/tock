// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

use kernel::utilities::registers::register_bitfields;

// mcycle is the lower XLEN bits of the number of elapsed cycles
register_bitfields![usize,
    pub mcycle [
        mcycle OFFSET(0) NUMBITS(crate::XLEN) []
    ]
];

// `mcycleh` is the higher XLEN bits of the number of elapsed cycles.
// It does not exist on riscv64.
#[cfg(not(target_arch = "riscv64"))]
register_bitfields![usize,
    pub mcycleh [
        mcycleh OFFSET(0) NUMBITS(crate::XLEN) []
    ]
];
