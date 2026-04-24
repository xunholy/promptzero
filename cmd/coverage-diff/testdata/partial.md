# Partial-match fixture

Half the link texts match known tools; half are gap candidates that do not
appear in the mock tool set. Expected gap count: 3.

## Known tools (will match)

- [device_info](https://example.com) - Get device info
- [nfc_read](https://example.com) - Read NFC tag

## Unknown tools (will be gaps)

- [magic_wand](https://example.com) - Hypothetical magic tool
- [alien_scanner](https://example.com) - Hypothetical alien scanner
- [quantum_leap](https://example.com) - Hypothetical quantum leap

## Inline code

`device_info` is known; `ghost_probe` is a gap.
