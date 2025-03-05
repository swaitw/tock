// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

//! Test the behavior of a single alarm.
//! To add this test, include the line
//! ```
//!    alarm_test::run_alarm(alarm);
//! ```
//! to the imix boot sequence, where `alarm` is a
//! `kernel::hil::Alarm`. The test sets up a series of
//! alarms of different durations and prints out when
//! they fire. They are large enough (and spaced out
//! enough that you should be able to tell if things
//! are working reasonably well. The module also uses
//! debug_gpio on pin XX so you can more precisely check
//! the timings with a logic analyzer.

use capsules_core::test::alarm_edge_cases::TestAlarmEdgeCases;
use kernel::debug;
use kernel::hil::time::Alarm;
use kernel::static_init;
use sam4l::ast::Ast;

pub unsafe fn run_alarm(ast: &'static Ast) {
    debug!("Starting alarm test.");
    let test = static_init_alarm_test(ast);
    test.run();
}

unsafe fn static_init_alarm_test(
    ast: &'static Ast,
) -> &'static TestAlarmEdgeCases<'static, Ast<'static>> {
    let test = static_init!(
        TestAlarmEdgeCases<'static, Ast<'static>>,
        TestAlarmEdgeCases::new(ast)
    );
    ast.set_alarm_client(test);
    test
}
