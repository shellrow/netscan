use std::net::UdpSocket;
use std::time::Duration;
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::Ipv4;
use crate::icmp;

pub fn get_router_ip(){
    let buf = [0u8; 0];
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => panic!("error!"),
    };
    let dest: &str = "192.168.11.1:80";
    socket.set_ttl(1).unwrap();
    socket.send_to(&buf, dest).unwrap();
    let protocol = Layer4(Ipv4(pnet::packet::ip::IpNextHeaderProtocols::Icmp));
    let (mut _tx, mut rx) = match pnet::transport::transport_channel(4096, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!("Error happened {}", e),
    };
    let timeout = Duration::from_millis(3000);
    let router_ip = icmp::receive_icmp_packets(&mut rx, pnet::packet::icmp::IcmpTypes::TimeExceeded, &timeout);
    match router_ip {
        Ok(ip) => {println!("{}", ip)},
        Err(e) => {println!("{}", e)},
    }
}

#[cfg(test)]
mod tests {
    use crate::udp;
    #[test]
    fn test_get_router_ip() {
        udp::get_router_ip();
    }
}
