use cortex_m::peripheral::NVIC;

use crate::{
    packet_id::IntoPacketId,
    rx::{RxPacket, RxRing},
    stm32::{Interrupt, ETHERNET_DMA},
    tx::TxRing,
    EthernetMAC, PacketId, RxError, RxRingEntry, TxError, TxRingEntry,
};

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Clone, Copy, Debug)]
pub struct Timestamp {
    seconds: u32,
    subseconds: u32,
}

impl Timestamp {
    pub const NANO_ROLLOVER: u32 = 999_999_999;
    pub const NORMAL_ROLLOVER: u32 = 0x7FFF_FFFF;
    pub const NANOS_PER_SECOND: u32 = 1_000_000_000;

    pub fn new(seconds: u32, subseconds: u32) -> Self {
        Self {
            seconds,
            subseconds,
        }
    }

    pub fn seconds(&self) -> u32 {
        let seconds_in_subseconds = self.subseconds / Self::NANOS_PER_SECOND;

        self.seconds + seconds_in_subseconds
    }

    pub fn nanos(&self) -> u32 {
        let nanos = self.subseconds % Self::NANOS_PER_SECOND;
        nanos
    }
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum TimestampError {
    NotYetTimestamped,
    IdNotFound,
}

/// Ethernet DMA.
pub struct EthernetDMA<'rx, 'tx> {
    eth_dma: ETHERNET_DMA,
    rx_ring: RxRing<'rx>,
    tx_ring: TxRing<'tx>,
}

impl<'rx, 'tx> EthernetDMA<'rx, 'tx> {
    /// Create and initialise the ethernet DMA
    ///
    /// # Note
    /// - Make sure that the buffers reside in a memory region that is
    /// accessible by the peripheral. Core-Coupled Memory (CCM) is
    /// usually not accessible.
    //
    // NOTE: eth_mac is unused, but required for initialization as
    // owning an [`EthernetMAC`] requires that all of it's checks
    // (GPIO, clock speed) have passed.
    pub fn new(
        #[allow(unused)] eth_mac: &EthernetMAC,
        eth_dma: ETHERNET_DMA,
        rx_buffer: &'rx mut [RxRingEntry],
        tx_buffer: &'tx mut [TxRingEntry],
    ) -> Self {
        // reset DMA bus mode register
        eth_dma.dmabmr.modify(|_, w| w.sr().set_bit());

        // Wait until done
        while eth_dma.dmabmr.read().sr().bit_is_set() {}

        // operation mode register
        eth_dma.dmaomr.modify(|_, w| {
            // Dropping of TCP/IP checksum error frames disable
            w.dtcefd()
                .set_bit()
                // Receive store and forward
                .rsf()
                .set_bit()
                // Disable flushing of received frames
                .dfrf()
                .set_bit()
                // Transmit store and forward
                .tsf()
                .set_bit()
                // Forward error frames
                .fef()
                .set_bit()
                // Operate on second frame
                .osf()
                .set_bit()
        });

        // bus mode register
        eth_dma.dmabmr.modify(|_, w| {
            // For any non-f107 chips, we must use enhanced descriptor format to support checksum
            // offloading and/or timestamps.
            #[cfg(not(feature = "stm32f107"))]
            let w = w.edfe().set_bit();

            unsafe {
                // Address-aligned beats
                w.aab()
                    .set_bit()
                    // Fixed burst
                    .fb()
                    .set_bit()
                    // Rx DMA PBL
                    .rdp()
                    .bits(32)
                    // Programmable burst length
                    .pbl()
                    .bits(32)
                    // Rx Tx priority ratio 2:1
                    .pm()
                    .bits(0b01)
                    // Use separate PBL
                    .usp()
                    .set_bit()
            }
        });

        let mut dma = EthernetDMA {
            eth_dma,
            rx_ring: RxRing::new(rx_buffer),
            tx_ring: TxRing::new(tx_buffer),
        };

        dma.rx_ring.start(&dma.eth_dma);
        dma.tx_ring.start(&dma.eth_dma);

        dma
    }

    /// Enable RX and TX interrupts
    ///
    /// In your handler you must call
    /// [`eth_interrupt_handler()`](fn.eth_interrupt_handler.html) to
    /// clear interrupt pending bits. Otherwise the interrupt will
    /// reoccur immediately.
    pub fn enable_interrupt(&self) {
        self.eth_dma.dmaier.modify(|_, w| {
            w
                // Normal interrupt summary enable
                .nise()
                .set_bit()
                // Receive Interrupt Enable
                .rie()
                .set_bit()
                // Transmit Interrupt Enable
                .tie()
                .set_bit()
        });

        // Enable ethernet interrupts
        unsafe {
            NVIC::unmask(Interrupt::ETH);
        }
    }

    /// Calls [`eth_interrupt_handler()`](fn.eth_interrupt_handler.html)
    pub fn interrupt_handler(&mut self) -> InterruptReasonSummary {
        let status = eth_interrupt_handler(&self.eth_dma);
        eth_interrupt_handler(&self.eth_dma);
        self.tx_ring.collect_timestamps();
        status
    }

    /// Is Rx DMA currently running?
    ///
    /// It stops if the ring is full. Call `recv_next()` to free an
    /// entry and to demand poll from the hardware.
    pub fn rx_is_running(&self) -> bool {
        self.rx_ring.running_state(&self.eth_dma).is_running()
    }

    /// Receive the next packet (if any is ready), or return `None`
    /// immediately.
    pub fn recv_next(&mut self, packet_id: Option<PacketId>) -> Result<RxPacket, RxError> {
        self.rx_ring
            .recv_next(&self.eth_dma, packet_id.map(|p| p.into()))
    }

    /// Is Tx DMA currently running?
    pub fn tx_is_running(&self) -> bool {
        self.tx_ring.is_running(&self.eth_dma)
    }

    /// Send a packet
    pub fn send<F: FnOnce(&mut [u8]) -> R, R>(
        &mut self,
        length: usize,
        packet_id: Option<PacketId>,
        f: F,
    ) -> Result<R, TxError> {
        let result = self.tx_ring.send(length, packet_id.map(|p| p.into()), f);
        self.tx_ring.demand_poll(&self.eth_dma);
        result
    }

    /// Get a timestamp for the given ID
    pub fn get_timestamp_for_id<'a, PKT>(
        &mut self,
        packet_id: PKT,
    ) -> Result<Timestamp, TimestampError>
    where
        PKT: IntoPacketId,
    {
        let Self {
            tx_ring, rx_ring, ..
        } = self;

        let internal_packet_id = packet_id.to_packet_id();

        tx_ring
            .get_timestamp_for_id(internal_packet_id.clone())
            .or_else(|_| rx_ring.get_timestamp_for_id(internal_packet_id))
    }
}

/// A summary of the reasons for the interrupt
/// that occured
pub struct InterruptReasonSummary {
    pub is_rx: bool,
    pub is_tx: bool,
    pub is_error: bool,
}

/// Call in interrupt handler to clear interrupt reason, when
/// [`enable_interrupt()`](struct.EthernetDMA.html#method.enable_interrupt).
///
/// There are two ways to call this:
///
/// * Via the [`EthernetDMA`](struct.EthernetDMA.html) driver instance that your interrupt handler has access to.
/// * By unsafely getting `Peripherals`.
pub fn eth_interrupt_handler(eth_dma: &ETHERNET_DMA) -> InterruptReasonSummary {
    let status = eth_dma.dmasr.read();

    let status = InterruptReasonSummary {
        is_rx: status.rs().bit_is_set(),
        is_tx: status.ts().bit_is_set(),
        is_error: status.ais().bit_is_set(),
    };

    eth_dma
        .dmasr
        .write(|w| w.nis().set_bit().ts().set_bit().rs().set_bit());

    status
}