use core::sync::atomic::Ordering;

use crate::logging::{debug, info, warn};
use crate::time::{Duration, with_timeout};
use bbqueue::{
    BBQueue,
    prod_cons::framed::FramedConsumer,
    traits::{coordination::Coord, notifier::maitake::MaiNotSpsc, storage::Inline},
};
use static_cell::ConstStaticCell;
use usb::{
    Builder, UsbDevice,
    driver::{Driver, Endpoint, EndpointIn},
    msos::{self, windows_version},
};

use crate::interface_manager::interface_impls::embassy_usb::TransmitError;

use super::{DEVICE_INTERFACE_GUIDS, UsbDeviceBuffers};
use core::sync::atomic::AtomicU8;
use embassy_sync::{blocking_mutex::raw::CriticalSectionRawMutex, watch::Watch};

struct ErgotHandler {}
static STINDX: AtomicU8 = AtomicU8::new(0xFF);
static HDLR: ConstStaticCell<ErgotHandler> = ConstStaticCell::new(ErgotHandler {});
pub(crate) static USB_SUSPEND: Watch<CriticalSectionRawMutex, bool, 2> = Watch::new_with(false);

/// A helper type for `static` storage of buffers and driver components
pub struct WireStorage<
    const CONFIG: usize = 256,
    const BOS: usize = 256,
    const CONTROL: usize = 64,
    const MSOS: usize = 256,
> {
    /// Usb buffer storage
    pub bufs_usb: ConstStaticCell<UsbDeviceBuffers<CONFIG, BOS, CONTROL, MSOS>>,
}

/// Transmitter worker task.
///
/// Holds each outgoing queue grant until the complete frame is submitted or
/// the endpoint is disabled. A host that stops reading applies backpressure
/// to the queue. `timeout_ms_per_frame` sets the warning threshold per USB
/// packet; exceeding it does not cancel a pending write.
pub async fn tx_worker<'a, D: Driver<'a>, const N: usize, C: Coord>(
    ep_in: &mut D::EndpointIn,
    rx: FramedConsumer<&'static BBQueue<Inline<N>, C, MaiNotSpsc>>,
    timeout_ms_per_frame: usize,
    max_usb_frame_size: usize,
) {
    assert!(max_usb_frame_size.is_power_of_two());
    info!("Started tx_worker");
    let mut pending = false;
    loop {
        ep_in.wait_enabled().await;

        info!("Endpoint marked connected");

        'connection: loop {
            let frame = rx.wait_read().await;

            debug!("Got frame to send len {}", frame.len());

            let res = send_all(
                ep_in,
                &frame,
                &mut pending,
                timeout_ms_per_frame,
                max_usb_frame_size,
            )
            .await;

            frame.release();

            match res {
                Ok(()) => {}
                Err(TransmitError::ConnectionClosed) => break 'connection,
            }
        }

        while let Ok(frame) = rx.read() {
            frame.release();
        }
    }
}

#[inline]
pub(super) async fn send_all<E>(
    ep_in: &mut E,
    out: &[u8],
    pending_frame: &mut bool,
    timeout_ms_per_frame: usize,
    max_usb_frame_size: usize,
) -> Result<(), TransmitError>
where
    E: EndpointIn,
{
    if out.is_empty() {
        return Ok(());
    }

    let frames = out.len().div_ceil(max_usb_frame_size);
    let timeout_ms = frames * timeout_ms_per_frame;

    let send_fut = async {
        if *pending_frame && ep_in.write(&[]).await.is_err() {
            return Err(TransmitError::ConnectionClosed);
        }
        *pending_frame = true;

        for ch in out.chunks(max_usb_frame_size) {
            if ep_in.write(ch).await.is_err() {
                return Err(TransmitError::ConnectionClosed);
            }
        }
        if (out.len() & (max_usb_frame_size - 1)) == 0 && ep_in.write(&[]).await.is_err() {
            return Err(TransmitError::ConnectionClosed);
        }

        *pending_frame = false;
        Ok(())
    };

    // Time out only the borrow: dropping an in-progress endpoint write
    // could leave a prefix on the bus. Keep the same future and queue grant
    // alive until it completes or reports a disabled endpoint.
    let mut send_fut = core::pin::pin!(send_fut);
    match with_timeout(Duration::from_millis(timeout_ms as u64), send_fut.as_mut()).await {
        Ok(result) => result,
        Err(_) => {
            warn!("USB transmit delayed; waiting for completion");
            send_fut.await
        }
    }
}

impl<const CONFIG: usize, const BOS: usize, const CONTROL: usize, const MSOS: usize>
    WireStorage<CONFIG, BOS, CONTROL, MSOS>
{
    /// Create a new, uninitialized static set of buffers
    pub const fn new() -> Self {
        Self {
            bufs_usb: ConstStaticCell::new(UsbDeviceBuffers::new()),
        }
    }

    /// Initialize the static storage, reporting as ergot compatible
    pub fn init_ergot<D: Driver<'static> + 'static>(
        &'static self,
        driver: D,
        config: usb::Config<'static>,
    ) -> (UsbDevice<'static, D>, D::EndpointIn, D::EndpointOut) {
        let bufs = self.bufs_usb.take();

        let mut builder = Builder::new(
            driver,
            config,
            &mut bufs.config_descriptor,
            &mut bufs.bos_descriptor,
            &mut bufs.msos_descriptor,
            &mut bufs.control_buf,
        );

        let hdlr = HDLR.take();
        builder.handler(hdlr);

        builder.msos_descriptor(windows_version::WIN8_1, 0);
        builder.msos_feature(msos::CompatibleIdFeatureDescriptor::new("WINUSB", ""));
        builder.msos_feature(msos::RegistryPropertyFeatureDescriptor::new(
            "DeviceInterfaceGUIDs",
            msos::PropertyData::RegMultiSz(DEVICE_INTERFACE_GUIDS),
        ));

        let mut function = builder.function(0xFF, 0, 0);
        let mut interface = function.interface();
        let stindx = interface.string();
        STINDX.store(stindx.0, Ordering::Relaxed);
        let mut alt = interface.alt_setting(0xFF, 0xCA, 0x7D, Some(stindx));
        let ep_out = alt.endpoint_bulk_out(None, bulk_options());
        let ep_in = alt.endpoint_bulk_in(None, bulk_options());
        drop(function);

        let usb = builder.build();

        (usb, ep_in, ep_out)
    }

    /// Initialize the static storage
    pub fn init<D: Driver<'static> + 'static>(
        &'static self,
        driver: D,
        config: usb::Config<'static>,
    ) -> (UsbDevice<'static, D>, D::EndpointIn, D::EndpointOut) {
        let (builder, wtx, wrx) = self.init_without_build(driver, config);
        let usb = builder.build();
        (usb, wtx, wrx)
    }

    /// Initialize the static storage, without building `Builder`
    pub fn init_without_build<D: Driver<'static> + 'static>(
        &'static self,
        driver: D,
        config: usb::Config<'static>,
    ) -> (Builder<'static, D>, D::EndpointIn, D::EndpointOut) {
        let bufs = self.bufs_usb.take();

        let mut builder = Builder::new(
            driver,
            config,
            &mut bufs.config_descriptor,
            &mut bufs.bos_descriptor,
            &mut bufs.msos_descriptor,
            &mut bufs.control_buf,
        );

        let hdlr = HDLR.take();
        builder.handler(hdlr);

        builder.msos_descriptor(windows_version::WIN8_1, 0);
        builder.msos_feature(msos::CompatibleIdFeatureDescriptor::new("WINUSB", ""));
        builder.msos_feature(msos::RegistryPropertyFeatureDescriptor::new(
            "DeviceInterfaceGUIDs",
            msos::PropertyData::RegMultiSz(DEVICE_INTERFACE_GUIDS),
        ));

        let mut function = builder.function(0xFF, 0, 0);
        let mut interface = function.interface();
        let stindx = interface.string();
        STINDX.store(stindx.0, Ordering::Relaxed);
        let mut alt = interface.alt_setting(0xFF, 0xCA, 0x7D, Some(stindx));
        let ep_out = alt.endpoint_bulk_out(None, bulk_options());
        let ep_in = alt.endpoint_bulk_in(None, bulk_options());
        drop(function);

        (builder, ep_in, ep_out)
    }
}

impl<const CONFIG: usize, const BOS: usize, const CONTROL: usize, const MSOS: usize> Default
    for WireStorage<CONFIG, BOS, CONTROL, MSOS>
{
    fn default() -> Self {
        Self::new()
    }
}

impl usb::Handler for ErgotHandler {
    fn suspended(&mut self, suspended: bool) {
        USB_SUSPEND.sender().send(suspended);
    }

    fn reset(&mut self) {
        USB_SUSPEND.sender().send(false);
    }

    fn get_string(&mut self, index: usb::types::StringIndex, lang_id: u16) -> Option<&str> {
        use usb::descriptor::lang_id;

        let stindx = STINDX.load(Ordering::Relaxed);
        if stindx == 0xFF {
            return None;
        }
        if lang_id == lang_id::ENGLISH_US && index.0 == stindx {
            Some("ergot")
        } else {
            None
        }
    }
}
