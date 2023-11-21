[crates-badge]: https://img.shields.io/crates/v/netscan.svg
[crates-url]: https://crates.io/crates/netscan
[license-badge]: https://img.shields.io/crates/l/netscan.svg
[examples-url]: https://github.com/shellrow/netscan/tree/main/examples

# netscan [![Crates.io][crates-badge]][crates-url] ![License][license-badge]
Cross-platform network scan library  
with the aim of being lightweight and fast. 

## Features
- Port Scan (IPv4, IPv6)
    - TCP SYN scan
    - TCP CONNECT scan
- Host Scan (IPv4, IPv6)
    - ICMP PING scan
    - TCP PING scan
    - UDP PING scan

## Usage
Add `netscan` to your dependencies  
```toml:Cargo.toml
[dependencies]
netscan = "0.22"
```

## Example
See [Examples][examples-url]

## Feature flags
The following feature flags can be used to enable/disable specific features.
#### `--feature service`
Enable service detection.      
#### `--feature os`
Enable TCP/IP Stack Fingerprinting.  
#### `--feature full`
Enable all of the above.

For more details see [Examples][examples-url]

## Supported platform
- Linux
- macOS
- Windows

## Note for Windows users
To build on Windows, follow the instructions below.
> ### Windows
> * You must use a version of Rust which uses the MSVC toolchain
> * You must have [npcap](https://nmap.org/npcap/) or [WinPcap](https://www.winpcap.org/) installed
>   (If using npcap, make sure to install with the "Install Npcap in WinPcap API-compatible Mode")
> * You must place `Packet.lib` from the [Npcap SDK](https://npcap.com/guide/npcap-devguide.html) or [WinPcap Developers pack](https://www.winpcap.org/devel.htm)
>   in a directory named `lib`, in the root of this repository. Alternatively, you can use any of the
>   locations listed in the `%LIB%`/`$Env:LIB` environment variables. For the 64 bit toolchain it is
>   in `<SDK>/Lib/x64/Packet.lib`, for the 32 bit toolchain, it is in `<SDK>/Lib/Packet.lib`.

## Additional Notes
This library requires the ability to create raw sockets.  Execute with administrator privileges.  
