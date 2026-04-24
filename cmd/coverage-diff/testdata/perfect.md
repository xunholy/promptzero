# Perfect-match fixture

Every link text in this file resolves to a tool that exists in the mock tool
set passed to classify() during tests. Expected gap count: 0.

## Tools

- [device_info](https://example.com) - Get device information
- [storage_list](https://example.com) - List files on SD card
- [nfc_read](https://example.com) - Read an NFC tag
- [subghz_rx](https://example.com) - Receive SubGHz signal

## Code example

```bash
device_info
storage_list /path
```

Inline: `nfc_read` is a core tool.
