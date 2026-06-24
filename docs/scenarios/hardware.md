# Hardware / GPIO scenarios

The Flipper has 8 exposed GPIO pins (PA7, PA6, PA4, PB3, PB2, PC3,
PC1, PC0), I²C on PC0/PC1 with external pull-ups, and the 1-Wire
iButton pad on the top-left.

## Identify an unknown PCB (recommended starting point)

> *"Run the black-box hardware recon workflow on whatever's hooked up
> to my GPIO header right now"*

Fires `workflow_hw_recon_blackbox_device`. Aggregates:
- `i2c_scan` (0x00–0x7F sweep)
- `onewire_search` (1-Wire bus enumeration)
- `gpio_read` across all 8 pins
- `bt_hci_info`, `device_info` as reference context

Returns a structured report with chip-ID hints for common I²C
addresses (0x3c OLED, 0x68 RTC/IMU, 0x76/0x77 BMP280, etc.).
[Transcript 15](../transcripts/15-workflow-hwrecon.json)

## Scan I²C specifically

> *"Scan the I2C bus for devices connected to the Flipper's GPIO
> header"*

Fires `i2c_scan`. No parameters. Tries the built-in CLI first; falls
back to the I²C Scanner FAP if the firmware doesn't ship the
command. [Transcript 11](../transcripts/11-i2c-scan.json)

Wiring reminder (the agent will tell you the same):
- SCL → PC0
- SDA → PC1
- GND → GND
- Power from the Flipper 3V3 (pin 9) or from an external supply
  sharing ground
- 4.7k–10k pull-ups on SDA and SCL to VCC (many breakouts include them)

## Enumerate 1-Wire devices

> *"Look for any 1-Wire devices on the iButton pad"*

Fires `onewire_search`. Returns every ROM code present; covers
Dallas iButtons, DS18B20 temperature sensors, etc.
[Transcript 12](../transcripts/12-onewire.json)

## Drive a GPIO pin

Set:

> *"Set GPIO PA7 high"* → `gpio_set(pin=PA7, value=1)`.

Read:

> *"Read GPIO PA7"* → `gpio_read(pin=PA7)`.

High-level context: the agent treats "turn on LED on PA7" and
"drive the relay on PA7" the same — both map to `gpio_set(value=1)`.

## Launch hardware-recon FAPs

If you've got the FAPs installed:

- *"Launch the UART Terminal so I can talk to a serial target"* →
  `loader_uart_terminal`.
- *"Launch SPI Mem Manager to read an SPI flash"* →
  `loader_spi_mem_manager`. Requires the FAP under `/ext/apps/`.
- *"Launch Unitemp to read this DHT22 sensor"* →
  `loader_unitemp`.
- *"Show me the spectrum analyzer"* → `loader_spectrum_analyzer`.
- *"Open ProtoView"* → `loader_protoview`.
- *"Launch the signal generator"* → `loader_signal_generator`.

All of these take no parameters. When uncertain about availability,
the agent will call `list_apps` first.
