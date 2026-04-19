# Infrared scenarios

## Learn a button from a real remote

> *"Try to learn an IR signal — I'll press a remote at the Flipper.
> Give it 8 seconds."*

Fires `ir_receive(timeout_seconds=8)`. Point the remote at the top
edge of the Flipper (IR receiver is up there), 5–20 cm away. If
nothing comes through, the tool returns a positioning tip rather
than a raw timeout error. [Transcript 31](../transcripts/31-ir-receive.json)

## Decode a saved remote file

> *"Decode /ext/infrared/livingroom_tv.ir and list every button"*

Fires `ir_decode_file`. Returns protocol + address + command per
button. Useful before transmitting to confirm the library has the
command you need.

## Browse the universal remote library

> *"List the buttons in the TV universal remote library"*

Fires `ir_universal_list(library=tv)`. Valid libraries:
`tv`, `ac`, `audio`, `projector`.

## Generate a remote from scratch

> *"Generate an IR remote file for a generic Samsung TV — generate
> only, do NOT deploy"*

Fires `generate_ir(description=…, deploy=false)`. Uses the gen LLM to
produce a full `.ir` file with all common buttons in the right
protocol (Samsung32 in this case).
[Transcript 14](../transcripts/14-gen-ir.json)

To write it to the card in one step, drop the "don't deploy":
*"Generate a Samsung TV remote and save it to /ext/infrared/samsung.ir"*.

## Transmit a decoded command (active IR)

> *"Send a Samsung32 TV power command: address 07 00 00 00, command
> 02 00 00 00"*

Fires `ir_transmit(protocol=Samsung32, address=…, command=…)`.
Classified `high` — confirmation-gated.

Raw timing:

> *"Send raw IR timing 9000 4500 560 560 560 1690 … at 38kHz"*

Fires `ir_transmit_raw(data=…)`.

## Brute-force a device (heavy)

> *"Brute-force TV power-off using /ext/infrared/tv_bruteforce.ir"*

Fires `ir_bruteforce(file=…, duration_seconds=60)`. Classified
`critical` — cycles through known protocols looking for a match.
