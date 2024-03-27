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
netscan = "0.27"
```

## Example
See [Examples][examples-url]

## Supported platform
- Linux
- macOS
- Windows

## Privileges
This library requires the ability to create raw sockets.  Execute with administrator privileges.  

## Note for Windows Users
If you are using Windows, please consider the following points before building and running:

- Npcap or WinPcap Installation:
    - Ensure that you have [Npcap](https://npcap.com/#download) or WinPcap installed on your system.
    - If using Npcap, make sure to install it with the "Install Npcap in WinPcap API-compatible Mode" option.
- Build Dependencies:
    - Place the Packet.lib file from the [Npcap SDK](https://npcap.com/#download) or WinPcap Developers pack in a directory named lib at the root of this repository.
    - You can use any of the locations listed in the %LIB% or $Env:LIB environment variables.
    - For the 64-bit toolchain, the Packet.lib is located in <SDK>/Lib/x64/Packet.lib.
    - For the 32-bit toolchain, the Packet.lib is located in <SDK>/Lib/Packet.lib.
