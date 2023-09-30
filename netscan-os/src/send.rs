use std::thread;
use crate::setting::{ProbeSetting, ProbeType, TcpProbeKind};
use crate::builder;
use cross_socket::{socket::DataLinkSocket, packet::tcp::TcpFlag};

pub(crate) fn send_packets(
    socket: &mut DataLinkSocket,
    probe_setting: &ProbeSetting
) {
    let mut tcp_syn_count: usize = 0;
    for probe_type in probe_setting.probe_types.clone() {
        match probe_type {
            ProbeType::TcpProbe => {
                tcp_syn_count += TcpProbeKind::VALUES.len();
            }
            ProbeType::TcpSynAckProbe | ProbeType::TcpEcnProbe => {
                tcp_syn_count += 1;
            }
            _ => {}
        }
    }
    for probe_type in probe_setting.probe_types.clone() {
        match probe_type {
            ProbeType::IcmpEchoProbe => {
                let packet: Vec<u8> = builder::build_icmp_probe_packet(probe_setting, probe_type);
                match socket.send_to(&packet) {
                    Ok(_) => {},
                    Err(_) => {}
                }
            }
            ProbeType::IcmpTimestampProbe => {
                let packet: Vec<u8> = builder::build_icmp_probe_packet(probe_setting, probe_type);
                match socket.send_to(&packet) {
                    Ok(_) => {},
                    Err(_) => {}
                }
            }
            ProbeType::IcmpAddressMaskProbe => {
                let packet: Vec<u8> = builder::build_icmp_probe_packet(probe_setting, probe_type);
                match socket.send_to(&packet) {
                    Ok(_) => {},
                    Err(_) => {}
                }
            }
            ProbeType::IcmpInformationProbe => {
                let packet: Vec<u8> = builder::build_icmp_probe_packet(probe_setting, probe_type);
                match socket.send_to(&packet) {
                    Ok(_) => {},
                    Err(_) => {}
                }
            }
            ProbeType::IcmpUnreachableProbe => {
                let packet: Vec<u8> = builder::build_udp_probe_packet(probe_setting);
                match socket.send_to(&packet) {
                    Ok(_) => {},
                    Err(_) => {}
                }
            }
            ProbeType::TcpProbe => {
                for tcp_probe_kind in TcpProbeKind::VALUES.iter().copied() {
                    let packet: Vec<u8> = builder::build_tcp_probe_packet(probe_setting, probe_type, Some(tcp_probe_kind));
                    match socket.send_to(&packet) {
                        Ok(_) => {},
                        Err(_) => {}
                    }
                    tcp_syn_count -= 1;
                    if tcp_syn_count > 0 {
                        thread::sleep(probe_setting.wait_time);
                        let ack_packet: Vec<u8> = builder::build_tcp_control_packet(probe_setting, vec![TcpFlag::Rst]);
                        match socket.send_to(&ack_packet) {
                            Ok(_) => {},
                            Err(_) => {}
                        }
                    }
                }
            }
            ProbeType::TcpSynAckProbe => {
                let packet: Vec<u8> = builder::build_tcp_probe_packet(probe_setting, probe_type, None);
                match socket.send_to(&packet) {
                    Ok(_) => {},
                    Err(_) => {}
                }
                tcp_syn_count -= 1;
                if tcp_syn_count > 0 {
                    thread::sleep(probe_setting.wait_time);
                    let ack_packet: Vec<u8> = builder::build_tcp_control_packet(probe_setting, vec![TcpFlag::Rst]);
                    match socket.send_to(&ack_packet) {
                        Ok(_) => {},
                        Err(_) => {}
                    }
                }
            }
            ProbeType::TcpRstAckProbe => {
                let packet: Vec<u8> = builder::build_tcp_probe_packet(probe_setting, probe_type, None);
                match socket.send_to(&packet) {
                    Ok(_) => {},
                    Err(_) => {}
                }
            }
            ProbeType::TcpEcnProbe => {
                let packet: Vec<u8> = builder::build_tcp_probe_packet(probe_setting, probe_type, None);
                match socket.send_to(&packet) {
                    Ok(_) => {},
                    Err(_) => {}
                }
                tcp_syn_count -= 1;
                if tcp_syn_count > 0 {
                    thread::sleep(probe_setting.wait_time);
                    let ack_packet: Vec<u8> = builder::build_tcp_control_packet(probe_setting, vec![TcpFlag::Rst]);
                    match socket.send_to(&ack_packet) {
                        Ok(_) => {},
                        Err(_) => {}
                    }
                }
            }
        }
    }
}
