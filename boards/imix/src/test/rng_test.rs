// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

//! This tests an underlying 32-bit entropy generator and the library
//! transformations between 8-bit and 32-bit entropy. To run this test,
//! add this line to the imix boot sequence:
//! ```
//!     test::rng_test::run_entropy32();
//! ```
//! This test takes a 32-bit entropy generator, puts its output into a
//! 32-8 conversion to be an 8-bit generator, puts that output into an
//! 8-to-32 conversion to be a 32-bit generator again, and makes this final
//! 32-bit entropy source be the tested RNG. This therefore tests not only
//! the underlying entropy source but also the conversion library.
//!
//! The expected output is a series of random numbers that should be
//! different on each invocation. Rigorous entropy tests are outside
//! the scope of this test.

use capsules_core::rng;
use capsules_core::test::rng::TestRng;
use kernel::hil::entropy::{Entropy32, Entropy8};
use kernel::hil::rng::Rng;
use kernel::static_init;
use sam4l::trng::Trng;

pub unsafe fn run_entropy32(trng: &'static Trng) {
    let t = static_init_test_entropy32(trng);
    t.run();
}

unsafe fn static_init_test_entropy32(trng: &'static Trng) -> &'static TestRng<'static> {
    let e1 = static_init!(
        rng::Entropy32To8<'static, Trng>,
        rng::Entropy32To8::new(trng)
    );
    trng.set_client(e1);
    let e2 = static_init!(
        rng::Entropy8To32<'static, rng::Entropy32To8<'static, Trng>>,
        rng::Entropy8To32::new(e1)
    );
    e1.set_client(e2);
    let er = static_init!(
        rng::Entropy32ToRandom<
            'static,
            rng::Entropy8To32<'static, rng::Entropy32To8<'static, Trng>>,
        >,
        rng::Entropy32ToRandom::new(e2)
    );
    e2.set_client(er);
    let test = static_init!(TestRng<'static>, TestRng::new(er));
    er.set_client(test);
    test
}
