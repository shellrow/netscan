[crates-badge]: https://img.shields.io/crates/v/netscan.svg
[crates-url]: https://crates.io/crates/netscan
[license-badge]: https://img.shields.io/crates/l/netscan.svg
[examples-url]: https://github.com/shellrow/netscan/tree/main/examples

# netscan [![Crates.io][crates-badge]][crates-url] ![License][license-badge]
Cross-platform network scan library  
with the aim of being lightweight and fast. 

## Features
- Port Scan
    - TCP SYN scan
    - TCP CONNECT scan
- Host Scan
    - ICMP PING scan
    - TCP PING scan

## Usage
Add `netscan` to your dependencies  
```toml:Cargo.toml
[dependencies]
netscan = "0.15.0"
```

## Example
See [Examples][examples-url]

## Feature flags
The following feature flags can be used to enable/disable specific features.
#### `--feature async`
Enable async scanning.(Default feature)  
#### `--feature service`
Enable service detection. (Experimental)      
#### `--feature os`
Enable TCP/IP Stack Fingerprinting. (Experimental)  
#### `--feature full`
Enable all of the above.

For more details see [Examples][examples-url]

## Supported platform
- Linux
- macOS
- Windows

## Note for Windows users
To build [libpnet](https://github.com/libpnet/libpnet) on Windows, follow the instructions below.
> ### Windows
> * You must use a version of Rust which uses the MSVC toolchain
> * You must have [WinPcap](https://www.winpcap.org/) or [npcap](https://nmap.org/npcap/) installed
>   (tested with version WinPcap 4.1.3) (If using npcap, make sure to install with the "Install Npcap in WinPcap API-compatible Mode")
> * You must place `Packet.lib` from the [WinPcap Developers pack](https://www.winpcap.org/devel.htm)
>   in a directory named `lib`, in the root of this repository. Alternatively, you can use any of the
>   locations listed in the `%LIB%`/`$Env:LIB` environment variables. For the 64 bit toolchain it is
>   in `WpdPack/Lib/x64/Packet.lib`, for the 32 bit toolchain, it is in `WpdPack/Lib/Packet.lib`.

[Source](https://github.com/libpnet/libpnet/blob/master/README.md#windows "libpnet#windows")

## Additional Notes
This library requires the ability to create raw sockets.  Execute with administrator privileges.  
