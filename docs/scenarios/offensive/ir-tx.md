# IR transmit scenarios

## Send a known protocol command

> *"Send a Samsung32 TV power command: address 07 00 00 00,
> command 02 00 00 00"*

Fires `ir_transmit(protocol=Samsung32, address=…, command=…)`.

Looking up the right address/command before transmitting:

> *"Decode /ext/infrared/samsung_tv.ir and then send the power button"*

Chains `ir_decode_file` → `ir_transmit`.

## Send raw IR timing

> *"Send raw IR timing 9000 4500 560 560 560 1690 560 1690 560 1690
> at 38kHz"*

Fires `ir_transmit_raw(data="9000 4500 …", frequency=38000)`.

Use this when you have a timing capture but don't know the protocol,
or when the protocol isn't in the decoder's table.

## Brute-force / universal remote

Universal remote from a library file:

> *"Use the TV universal remote to turn off any nearby TV"*

The agent launches the universal remote flow (usually via
`loader_open(app_name=Infrared, args=universal tv)` or the
`ir_bruteforce` tool depending on context).

Explicit brute force:

> *"Brute-force TV power using /ext/infrared/tv_bruteforce.ir for
> 60 seconds"* → `ir_bruteforce(file=…, duration_seconds=60)`.
Classified `critical`.
