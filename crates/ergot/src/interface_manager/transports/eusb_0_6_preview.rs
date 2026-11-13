//! USB bulk endpoint RxWorker (embassy-usb v0.6).
//!
//! Generic over any [`FrameProcessor`], so it works with [`DirectEdge`],
//! [`Router`], or any future profile.
//!
//! [`FrameProcessor`]: crate::interface_manager::FrameProcessor
//! [`DirectEdge`]: crate::interface_manager::profiles::direct_edge::DirectEdge
//! [`Router`]: crate::interface_manager::profiles::router::Router

use crate::interface_manager::interface_impls::embassy_usb::eusb_0_6_preview::USB_SUSPEND;
use embassy_usb_0_6_preview as usb;

include!("eusb_v0_6_shared.rs");
