use super::setting::{ProbeSetting, ProbeType};
use cross_socket::socket::DataLinkSocket;

pub(crate) fn send_packets(
    socket: &mut DataLinkSocket,
    probe_setting: &ProbeSetting
) {
    for probe_type in probe_setting.probe_types.clone() {
        match probe_type {
            ProbeType::IcmpEchoProbe => {
                let packet: Vec<u8> = crate::builder::build_icmp_probe_packet(probe_setting, probe_type);
                match socket.send_to(&packet) {
                    Ok(_) => {},
                    Err(_) => {}
                }
            }
            ProbeType::IcmpTimestampProbe => {
                let packet: Vec<u8> = crate::builder::build_icmp_probe_packet(probe_setting, probe_type);
                match socket.send_to(&packet) {
                    Ok(_) => {},
                    Err(_) => {}
                }
            }
            ProbeType::IcmpAddressMaskProbe => {
                let packet: Vec<u8> = crate::builder::build_icmp_probe_packet(probe_setting, probe_type);
                match socket.send_to(&packet) {
                    Ok(_) => {},
                    Err(_) => {}
                }
            }
            ProbeType::IcmpInformationProbe => {
                let packet: Vec<u8> = crate::builder::build_icmp_probe_packet(probe_setting, probe_type);
                match socket.send_to(&packet) {
                    Ok(_) => {},
                    Err(_) => {}
                }
            }
            ProbeType::IcmpUnreachableProbe => {
                let packet: Vec<u8> = crate::builder::build_udp_probe_packet(probe_setting);
                match socket.send_to(&packet) {
                    Ok(_) => {},
                    Err(_) => {}
                }
            }
            ProbeType::TcpProbe => {
                for tcp_probe_kind in crate::setting::TcpProbeKind::VALUES.iter().copied() {
                    let packet: Vec<u8> = crate::builder::build_tcp_probe_packet(probe_setting, probe_type, Some(tcp_probe_kind));
                    match socket.send_to(&packet) {
                        Ok(_) => {},
                        Err(_) => {}
                    }
                }
            }
            ProbeType::TcpSynAckProbe => {
                let packet: Vec<u8> = crate::builder::build_tcp_probe_packet(probe_setting, probe_type, None);
                match socket.send_to(&packet) {
                    Ok(_) => {},
                    Err(_) => {}
                }
            }
            ProbeType::TcpRstAckProbe => {
                let packet: Vec<u8> = crate::builder::build_tcp_probe_packet(probe_setting, probe_type, None);
                match socket.send_to(&packet) {
                    Ok(_) => {},
                    Err(_) => {}
                }
            }
            ProbeType::TcpEcnProbe => {
                let packet: Vec<u8> = crate::builder::build_tcp_probe_packet(probe_setting, probe_type, None);
                match socket.send_to(&packet) {
                    Ok(_) => {},
                    Err(_) => {}
                }
            }
        }
    }
}
