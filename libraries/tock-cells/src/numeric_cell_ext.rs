// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

//! `NumericCellExt` extension trait for `Cell`s.
//!
//! Adds a suite of convenience functions to `Cell`s that contain numeric
//! types. Cells that contains types that can meaningfully execute arithmetic
//! operations can use mechanisms such as `cell.add(val)` rather than
//! `cell.set(cell.get() + val)`.
//!
//! To use these traits, simply pull them into scope:
//!
//! ```rust
//! extern crate tock_cells;
//! use tock_cells::numeric_cell_ext::NumericCellExt;
//! ```

use core::cell::Cell;
use core::ops::{Add, Sub};

pub trait NumericCellExt<T>
where
    T: Copy + Add + Sub,
{
    /// Add the passed in `val` to the stored value.
    fn add(&self, val: T);

    /// Subtract the passed in `val` from the stored value.
    fn subtract(&self, val: T);

    /// Add 1 to the stored value.
    fn increment(&self);

    /// Subtract 1 from the stored value.
    fn decrement(&self);

    /// Return the current value and then add 1 to the stored value.
    fn get_and_increment(&self) -> T;

    /// Return the current value and then subtract 1 from the stored value.
    fn get_and_decrement(&self) -> T;
}

impl<T> NumericCellExt<T> for Cell<T>
where
    T: Add<Output = T> + Sub<Output = T> + Copy + From<usize>,
{
    fn add(&self, val: T) {
        self.set(self.get() + val);
    }

    fn subtract(&self, val: T) {
        self.set(self.get() - val);
    }

    fn increment(&self) {
        self.set(self.get() + T::from(1_usize));
    }

    fn decrement(&self) {
        self.set(self.get() - T::from(1_usize));
    }

    fn get_and_increment(&self) -> T {
        let ret = self.get();
        self.set(ret + T::from(1_usize));
        ret
    }

    fn get_and_decrement(&self) -> T {
        let ret = self.get();
        self.set(ret - T::from(1_usize));
        ret
    }
}
