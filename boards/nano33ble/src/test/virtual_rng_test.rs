// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

//! Test file for the virtual_rng
//! To run this test, include the code
//! ```
//!    test::virtual_rng_test::run(&base_peripherals.trng);
//! ```

use capsules_core::rng;
use capsules_core::test::virtual_rng::TestRng;
use kernel::hil::rng::Rng;
use kernel::{debug, static_init};

pub unsafe fn run(trng: &'static nrf52840::trng::Trng) {
    debug!("Starting virtual_rng get tests:");
    let rng_obj = static_init!(
        rng::Entropy32ToRandom<'static, nrf52840::trng::Trng>,
        rng::Entropy32ToRandom::new(trng)
    );

    // Create virtual rng mux device
    let mux = static_init!(
        capsules_core::virtualizers::virtual_rng::MuxRngMaster<'static>,
        capsules_core::virtualizers::virtual_rng::MuxRngMaster::new(rng_obj)
    );

    // Create all devices for the virtual rng
    let device1 = static_init!(
        capsules_core::virtualizers::virtual_rng::VirtualRngMasterDevice<'static>,
        capsules_core::virtualizers::virtual_rng::VirtualRngMasterDevice::new(mux)
    );
    let device2 = static_init!(
        capsules_core::virtualizers::virtual_rng::VirtualRngMasterDevice<'static>,
        capsules_core::virtualizers::virtual_rng::VirtualRngMasterDevice::new(mux)
    );
    let device3 = static_init!(
        capsules_core::virtualizers::virtual_rng::VirtualRngMasterDevice<'static>,
        capsules_core::virtualizers::virtual_rng::VirtualRngMasterDevice::new(mux)
    );

    // Create independent tests for each device
    let test_device_1 = static_init!(TestRng<'static>, TestRng::new(1, device1));

    let test_device_2 = static_init!(TestRng<'static>, TestRng::new(2, device2));

    let test_device_3 = static_init!(TestRng<'static>, TestRng::new(3, device3));

    // Set clients for each device
    device1.set_client(test_device_1);
    device2.set_client(test_device_2);
    device3.set_client(test_device_3);

    // // Get set number of random values for each device and interleave requests
    test_device_1.get_random_nums();
    test_device_2.get_random_nums();
    test_device_3.get_random_nums();
}
