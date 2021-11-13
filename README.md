[crates-badge]: https://img.shields.io/crates/v/netscan.svg
[crates-url]: https://crates.io/crates/netscan
[license-badge]: https://img.shields.io/crates/l/netscan.svg
[examples-url]: https://github.com/shellrow/netscan/tree/main/examples

# netscan [![Crates.io][crates-badge]][crates-url] ![License][license-badge]
Cross-platform network scan library  
with the aim of being lightweight and fast. 

## Features
- Port Scan
- Host Scan
- Async Port Scan (Currently only Unix-Like OS is supported)
- Async Host Scan (Currently only Unix-Like OS is supported)

## Usage
Add `netscan` to your dependencies  
```toml:Cargo.toml
[dependencies]
netscan = "0.7.0"
```

## Example
Port Scan Example
```rust
extern crate netscan;
use netscan::blocking::PortScanner;
use netscan::setting::{ScanType, Destination};
use std::time::Duration;
use std::net::{IpAddr, Ipv4Addr};

fn main() {
    let mut port_scanner = match PortScanner::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 4))) {
        Ok(scanner) => (scanner),
        Err(e) => panic!("Error creating scanner: {}", e),
    };
    let dst_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 8));
    //let dst: Destination = Destination::new(dst_ip, vec![22, 80, 443]);
    let dst: Destination = Destination::new_with_port_range(dst_ip, 1, 1000);
    port_scanner.add_destination(dst);
    port_scanner.set_scan_type(ScanType::TcpSynScan);
    port_scanner.set_timeout(Duration::from_millis(10000));
    port_scanner.set_wait_time(Duration::from_millis(100));
    port_scanner.run_scan();
    let result = port_scanner.get_scan_result();
    println!("Status: {:?}", result.scan_status);
    println!("Open Ports:");
    for port in result.ports {
        println!("{:?}", port);
    }
    println!("Scan Time: {:?}", result.scan_time);
}
```

For more details see [Examples][examples-url]

## Supported platform
- Linux
- macOS
- Windows

## Additional Notes
This library requires the ability to create raw sockets.  Execute with administrator privileges.  
