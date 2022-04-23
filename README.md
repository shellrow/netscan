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
netscan = "0.8.4"
```

## Example
Port Scan Example
```rust
use netscan::blocking::PortScanner;
use netscan::setting::{ScanType, Destination};
use std::time::Duration;
use std::net::{IpAddr, Ipv4Addr};

fn main() {
    let mut port_scanner = match PortScanner::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 4))) {
        Ok(scanner) => (scanner),
        Err(e) => panic!("Error creating scanner: {}", e),
    };
    // Add scan target
    let dst_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 8));
    //let dst: Destination = Destination::new(dst_ip, vec![22, 80, 443]);
    let dst: Destination = Destination::new_with_port_range(dst_ip, 1, 1000);
    port_scanner.add_destination(dst);
    // Set options
    port_scanner.set_scan_type(ScanType::TcpSynScan);
    port_scanner.set_timeout(Duration::from_millis(10000));
    port_scanner.set_wait_time(Duration::from_millis(100));
    //port_scanner.set_send_rate(Duration::from_millis(1));
    // Run scan 
    let result = port_scanner.scan();
    // Print results 
    println!("Status: {:?}", result.scan_status);
    println!("Results:");
    for (ip, ports) in result.result_map {
        println!("{}", ip);
        for port in ports {
            println!("{:?}", port);
        }
    }
    println!("Scan Time: {:?}", result.scan_time);
}
```

## Feature flags
The following feature flags can be used to enable/disable specific features.
#### `--feature async`
Enable async scanning.  
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
