// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

//! Interface for touch input devices

use crate::ErrorCode;

/// Touch Event Status
#[derive(Debug, Copy, Clone)]
pub enum TouchStatus {
    Unstarted,
    Pressed,
    Released,
    Moved,
}

/// Gesture event
#[derive(Debug, Copy, Clone)]
pub enum GestureEvent {
    SwipeUp,
    SwipeDown,
    SwipeLeft,
    SwipeRight,
    ZoomIn,
    ZoomOut,
}

/// A single touch event's data
#[derive(Copy, Clone)]
pub struct TouchEvent {
    pub status: TouchStatus,
    /// touch (x, y) position
    pub x: u16,
    pub y: u16,

    /// Numeric ID assigned to this touch. This ID allows the client to
    /// to match different `TouchEvent`s to the same physical touch.
    ///
    /// The driver must assign a unique ID to each touch.
    pub id: usize,

    /// Optional scaled value for the size of the touch. A larger value
    /// corresponds to a "fatter" touch. The size values range from 0
    /// to 65535.
    ///
    /// If a touchscreen does not provide information about the size of the touch,
    /// this must be set to `None`.
    pub size: Option<u16>,

    /// Optional scaled value for the pressure of the touch. A larger value
    /// corresponds to a "firmer" press. The pressure values range from 0
    /// to 65536.
    ///
    /// If a touchscreen does not provide information about the pressure of a touch,
    /// this must be set to `None`.
    pub pressure: Option<u16>,
}

/// Single touch panels should implement this
pub trait Touch<'a> {
    /// Enable the touch panel
    ///
    /// returns Ok(()) even if device is already enabled
    fn enable(&self) -> Result<(), ErrorCode>;

    /// Disable the touch panel
    ///
    /// returns Ok(()) even if device is already disabled
    fn disable(&self) -> Result<(), ErrorCode>;

    /// Set the touch client
    fn set_client(&self, touch_client: &'a dyn TouchClient);
}

/// Multi-touch panels should implement this
pub trait MultiTouch<'a> {
    /// Enable the touche panel
    ///
    /// returns Ok(()) even if device is already enabled
    fn enable(&self) -> Result<(), ErrorCode>;

    /// Disable the touch panel
    ///
    /// returns Ok(()) even if device is already disabled
    fn disable(&self) -> Result<(), ErrorCode>;

    /// Returns the number of maximum concurently supported touches.
    fn get_num_touches(&self) -> usize;

    /// Returns the touch event at index or `None`.
    ///
    /// This function must be called in the same interrupt
    /// as the event, otherwise data might not be available.
    fn get_touch(&self, index: usize) -> Option<TouchEvent>;

    /// Set the multi-touch client
    fn set_client(&self, multi_touch_client: &'a dyn MultiTouchClient);
}

/// The single touch client
pub trait TouchClient {
    /// Report a touch event
    fn touch_event(&self, touch_event: TouchEvent);
}

/// The multi touch client
pub trait MultiTouchClient {
    /// Report a multi touch event
    /// num touches represents the number of touches detected
    fn touch_events(&self, touch_events: &[TouchEvent], len: usize);
}

/// Touch panels that support gestures
pub trait Gesture<'a> {
    /// Set the gesture client
    fn set_client(&self, gesture_client: &'a dyn GestureClient);
}

/// The gesture client
pub trait GestureClient {
    fn gesture_event(&self, gesture_event: GestureEvent);
}
