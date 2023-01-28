# Rust Ethernet Driver for STM32F* microcontrollers

[![Build Status](https://travis-ci.org/stm32-rs/stm32-eth.svg?branch=master)](https://travis-ci.org/stm32-rs/stm32-eth)

## Supported microcontrollers

* STM32F107
* STM32F4xx
* STM32F7xx

Pull requests are welcome :)

## Usage

Add one of the following to the `[dependencies]` section in your `Cargo.toml` (with the correct MCU specified):

```toml
stm32-eth = { version = "0.3.0", features = ["stm32f429"] } # For stm32f4xx-like MCUs
stm32-eth = { version = "0.3.0", features = ["stm32f767"] } # For stm32f7xx-like MCUs
stm32-eth = { version = "0.3.0", features = ["stm32f107"] } # For stm32f107
```

`stm32_eth` re-exports the underlying HAL as `stm32_eth::hal`.

In `src/main.rs` add:

```rust,no_run
use stm32_eth::{
    hal::gpio::GpioExt,
    hal::rcc::RccExt,
    stm32::Peripherals,
    RingEntry,
    EthPins,
};
use fugit::RateExtU32;

fn main() {
    let p = Peripherals::take().unwrap();

    let rcc = p.RCC.constrain();
    // HCLK must be at least 25MHz to use the ethernet peripheral
    let clocks = rcc.cfgr.sysclk(32.MHz()).hclk(32.MHz()).freeze();

    let gpioa = p.GPIOA.split();
    let gpiob = p.GPIOB.split();
    let gpioc = p.GPIOC.split();
    let gpiog = p.GPIOG.split();

    let eth_pins = EthPins {
        ref_clk: gpioa.pa1,
        crs: gpioa.pa7,
        tx_en: gpiog.pg11,
        tx_d0: gpiog.pg13,
        tx_d1: gpiob.pb13,
        rx_d0: gpioc.pc4,
        rx_d1: gpioc.pc5,
    };

    let mut rx_ring: [RingEntry<_>; 16] = Default::default();
    let mut tx_ring: [RingEntry<_>; 8] = Default::default();
    let (mut eth_dma, _eth_mac) = stm32_eth::new(
        p.ETHERNET_MAC,
        p.ETHERNET_MMC,
        p.ETHERNET_DMA,
        &mut rx_ring[..],
        &mut tx_ring[..],
        clocks,
        eth_pins,
    )
    .unwrap();
    eth_dma.enable_interrupt();

    if let Ok(pkt) = eth_dma.recv_next() {
        // handle received pkt
    }

    let size = 42;
    eth_dma.send(size, |buf| {
        // write up to `size` bytes into buf before it is being sent
    }).expect("send");
}
```


## `smoltcp` support

Use feature-flag `smoltcp-phy`

## Examples

The examples should run and compile on any MCU that has an 802.3 compatible PHY capable of generating the required 50 MHz clock signal connected to the default RMII pins.

The examples use `defmt` and `defmt_rtt` for logging, and `panic_probe` over `defmt_rtt` for printing panic backtraces.

##### Alternative pin configuration & HSE

If the board you're developing for has a High Speed External oscillator connected to the correct pins, the HSE configuration can be activated by setting the `EXAMPLE_HSE` environment variable to one of `oscillator` or `bypass` when compiling.

If the board you're developing for uses the nucleo pinout (PG11 and PG13 instead of PB11 and PB12), the pin configuration can be changed by setting the `EXAMPLE_PINS` environment variable to `nucleo` when compiling.

### Building examples
To build an example, run the following command:
```bash
cargo build --release --example <example> --features <MCU feature>,<additional required features> --target <MCU compilation target>
```

For example, if we wish to build the `ip` example for an `stm32f429`, we should run the following command:

```bash
cargo build --release --example ip \
        --features stm32f429,defmt,smoltcp-phy,smoltcp/defmt,smoltcp/socket-tcp \
        --target thumbv7em-none-eabihf
```

If we wish to build the `arp` example for a Nucleo-F767ZI with a HSE oscillator:

```bash
EXAMPLE_HSE=bypass EXAMPLE_PINS=nucleo \
cargo build --release --example arp \
    --features stm32f767
```

### Running examples
Install `probe-run` with `cargo install probe-run --version '~0.3'`

Find the correct value for `PROBE_RUN_CHIP` for your MCU from the list provided by `probe-run --list-chips`.

Ensure that `probe-run` can attach to your MCU

Then, run the following command:
```bash
DEFMT_LOG=info PROBE_RUN_CHIP=<probe-run chip> \
cargo run --release --example <example> \
    --features <MCU feature>,<additional required features> \
    --target <MCU compilation target>
```

For example, if we wish to run the `rtic-echo` example on an `STM32F107RCT6`, we should run the following command:

```bash
DEFMT_LOG=info PROBE_RUN_CHIP=STM32F107RC cargo run --release --example rtic-echo \
    --features stm32f107,rtic-echo-example \
    --target thumbv7m-none-eabi
```

Or, if we want to run the `arp` example on a Nucleo-F767ZI with a HSE oscillator:

```bash
DEFMT_LOG=info PROBE_RUN_CHIP=STM32F767ZGTx \
EXAMPLE_PINS=nucleo EXAMPLE_HSE=oscillator  \
cargo run --release --example arp \
    --features stm32f767 \
    --target thumbv7em-none-eabihf
```