# sign-module

A kernel module signing tool for Fedora Linux with XZ compression support.

## Features

- Kernel-standard module signing
- XZ compressed module support (.ko.xz)
- Memory-optimized processing
- Automatic signature stripping

## Requirements

- OpenSSL 3.x
- liblzma 5.4+
- GCC with C17 support

## Build

```bash
make
```

## Usage

```bash
./sign-module <hash> <private_key.pem> <x509.der|.pem> <module.ko[.xz]>
```

Example:
```bash
./sign-module sha256 signing_key.pem signing_key.x509 nvidia.ko.xz
```

## Why this tool?

Fedora Linux kernel modules are XZ compressed, requiring decompression before signing and recompression afterward. This tool handles the entire workflow automatically.

Future compression formats (zstd, etc.) can be added as Fedora adopts them.

## License

MIT License
