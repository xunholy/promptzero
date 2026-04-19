# UI control scenarios

Drive the Flipper through its built-in UI — launch apps, simulate
button presses, blink LEDs, buzz the motor.

## Launch and close an app

> *"Open the NFC app on my Flipper, tell me what app is running,
> then close it"*

Fires `loader_open(app_name=NFC)` → `loader_info` → `loader_close`.
The middle `loader_info` call is the agent verifying the launch
succeeded before it claims the apps opened — that's a good pattern.
[Transcript 25](../transcripts/25-loader-flow.json)

Common app names: `NFC`, `SubGHz`, `125 kHz RFID`, `iButton`,
`Infrared`, `GPIO`, `Bad KB`, `U2F`, `Momentum`.

Pass arguments to a FAP:

> *"Open the GPIO app with argument `--help`"* →
> `loader_open(app_name=GPIO, args=--help)`.

## Navigate the UI

> *"Press OK, then down twice, then OK on the Flipper UI"*

Fires three `input_send` calls. Events:
- buttons: `up`, `down`, `left`, `right`, `ok`, `back`
- event types: `press`, `release`, `short`, `long`, `repeat`

Long-press:

> *"Long-press the back button"* →
> `input_send(button=back, event_type=long)`.

## Blink the LEDs

> *"Blink my Flipper's LEDs red, green, blue, then turn them all off"*

Six sequential `led_set` calls. Channels: `r`, `g`, `b`, `bl`
(LCD backlight). Value: 0–255.
[Transcript 04](../transcripts/04-led-blink.json)

Backlight dim:

> *"Dim the LCD backlight to 20%"* →
> `led_set(channel=bl, value=51)`.

## Buzz the motor

> *"Vibrate the Flipper briefly"*

Fires `vibro(on=true)` → `vibro(on=false)`.
[Transcript 07](../transcripts/07-vibro.json)

Use it as "I heard you" feedback in a longer script:

> *"After scanning, blink green and vibrate once"* →
> chains `led_set` + `vibro`.

## Tail the firmware debug log

> *"Tail the Flipper debug log for 5 seconds while I do stuff on the
> UI"*

Fires `log_stream(duration_seconds=5)`. Read-only; handy when an app
is misbehaving and you want the firmware's own log output.

## Reboot

> *"Reboot my Flipper"*

Fires `device_reboot`. Serial disconnects while the unit restarts —
in the REPL, use `/reconnect` once it's back. Classified `high`.

DFU mode (rescue / reflash):

> *"Put my Flipper in DFU mode so I can reflash it"*

Fires `power_reboot_dfu`. Classified `critical`. Only do this if you
have `qFlipper` or `dfu-util` ready — there's no firmware running
after this, USB is in DFU mode, recovery requires a reflash.
