use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;

pub trait EndPoints {
    fn get_source(&self) -> String;
    fn get_destination(&self) -> String;
    fn get_payload(&self) -> &[u8];
}

impl<'a> EndPoints for Ipv4Packet<'a> {
    fn get_source(&self) -> String {
        self.get_source().to_string()
    }

    fn get_destination(&self) -> String {
        self.get_destination().to_string()
    }

    fn get_payload(&self) -> &[u8] {
        self.payload()
    }
}

impl<'a> EndPoints for Ipv6Packet<'a> {
    fn get_source(&self) -> String {
        self.get_source().to_string()
    }

    fn get_destination(&self) -> String {
        self.get_destination().to_string()
    }

    fn get_payload(&self) -> &[u8] {
        self.payload()
    }
}

impl<'a> EndPoints for TcpPacket<'a> {
    fn get_source(&self) -> String {
        self.get_source().to_string()
    }

    fn get_destination(&self) -> String {
        self.get_destination().to_string()
    }

    fn get_payload(&self) -> &[u8] {
        self.payload()
    }
}

impl<'a> EndPoints for UdpPacket<'a> {
    fn get_source(&self) -> String {
        self.get_source().to_string()
    }

    fn get_destination(&self) -> String {
        self.get_destination().to_string()
    }

    fn get_payload(&self) -> &[u8] {
        self.payload()
    }
}
