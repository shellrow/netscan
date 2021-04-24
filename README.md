[crates-badge]: https://img.shields.io/crates/v/netscan.svg
[crates-url]: https://crates.io/crates/netscan
[license-badge]: https://img.shields.io/crates/l/netscan.svg
[examples-url]: https://github.com/shellrow/netscan/tree/main/examples

# netscan [![Crates.io][crates-badge]][crates-url] ![License][license-badge]
Cross-platform network scan library  
with the aim of being lightweight and fast. 

## Features
- PORT SCAN
- HOST SCAN

## Usage
Add `netscan` to your dependencies  
```toml:Cargo.toml
[dependencies]
netscan = "0.1.0"
```

## Example
Port Scan Example
```rust
extern crate netscan;
use netscan::PortScanner;
use netscan::PortScanType;
use netscan::ScanStatus;
use std::time::Duration;

fn main() {
    let mut port_scanner = match PortScanner::new(None) {
        Ok(scanner) => (scanner),
        Err(e) => panic!("Error creating scanner: {}", e),
    };
    port_scanner.set_target_ipaddr("192.168.1.8");
    port_scanner.set_range(1, 1000);
    //port_scanner.add_target_port(22);
    //port_scanner.add_target_port(80);
    //port_scanner.add_target_port(443);
    port_scanner.set_scan_type(PortScanType::SynScan);
    port_scanner.set_timeout(Duration::from_millis(10000));
    //port_scanner.set_wait_time(Duration::from_millis(100));
    port_scanner.run_scan();
    let result = port_scanner.get_result();
    print!("Status: ");
    match result.scan_status {
        ScanStatus::Done => {println!("Normal end")},
        ScanStatus::Timeout => {println!("Timed out")},
        _ => {println!("Error")},
    }
    println!("Open Ports:");
    for port in result.open_ports {
        println!("{}", port);
    }
    println!("Scan Time: {:?}", result.scan_time);
    if port_scanner.get_wait_time() > Duration::from_millis(0) {
        println!("(Including {:?} of wait time)", port_scanner.get_wait_time());
    }
}
```

For more details see [Examples][examples-url]

## Supported platform
- Linux
- macOS(OS X)
- Windows

## Additional Notes
This library requires the ability to create raw sockets.  Execute with root user privileges.  
