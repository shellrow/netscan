use std::thread;
use crate::setting::{ProbeSetting, ProbeType, TcpProbeKind};
use crate::builder;
use xenet::packet::tcp::TcpFlags;
use xenet::datalink::DataLinkSender;

pub(crate) fn send_packets(
    sender: &mut Box<dyn DataLinkSender>,
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
                match sender.send(&packet) {
                    Some(_r) => {
                        // TODO: Handle error
                    }
                    None => {}
                }
            }
            ProbeType::IcmpTimestampProbe => {
                let packet: Vec<u8> = builder::build_icmp_probe_packet(probe_setting, probe_type);
                match sender.send(&packet) {
                    Some(_r) => {
                        // TODO: Handle error
                    }
                    None => {}
                }
            }
            ProbeType::IcmpAddressMaskProbe => {
                let packet: Vec<u8> = builder::build_icmp_probe_packet(probe_setting, probe_type);
                match sender.send(&packet) {
                    Some(_r) => {
                        // TODO: Handle error
                    }
                    None => {}
                }
            }
            ProbeType::IcmpInformationProbe => {
                let packet: Vec<u8> = builder::build_icmp_probe_packet(probe_setting, probe_type);
                match sender.send(&packet) {
                    Some(_r) => {
                        // TODO: Handle error
                    }
                    None => {}
                }
            }
            ProbeType::IcmpUnreachableProbe => {
                let packet: Vec<u8> = builder::build_udp_probe_packet(probe_setting);
                match sender.send(&packet) {
                    Some(_r) => {
                        // TODO: Handle error
                    }
                    None => {}
                }
            }
            ProbeType::TcpProbe => {
                for tcp_probe_kind in TcpProbeKind::VALUES.iter().copied() {
                    let packet: Vec<u8> = builder::build_tcp_probe_packet(probe_setting, probe_type, Some(tcp_probe_kind));
                    match sender.send(&packet) {
                        Some(_r) => {
                            // TODO: Handle error
                        }
                        None => {}
                    }
                    tcp_syn_count -= 1;
                    if tcp_syn_count > 0 {
                        thread::sleep(probe_setting.wait_time);
                        let ack_packet: Vec<u8> = builder::build_tcp_control_packet(probe_setting, TcpFlags::RST);
                        match sender.send(&ack_packet) {
                            Some(_r) => {
                                // TODO: Handle error
                            }
                            None => {}
                        }
                    }
                }
            }
            ProbeType::TcpSynAckProbe => {
                let packet: Vec<u8> = builder::build_tcp_probe_packet(probe_setting, probe_type, None);
                match sender.send(&packet) {
                    Some(_r) => {
                        // TODO: Handle error
                    }
                    None => {}
                }
                tcp_syn_count -= 1;
                if tcp_syn_count > 0 {
                    thread::sleep(probe_setting.wait_time);
                    let ack_packet: Vec<u8> = builder::build_tcp_control_packet(probe_setting, TcpFlags::RST);
                    match sender.send(&ack_packet) {
                        Some(_r) => {
                            // TODO: Handle error
                        }
                        None => {}
                    }
                }
            }
            ProbeType::TcpRstAckProbe => {
                let packet: Vec<u8> = builder::build_tcp_probe_packet(probe_setting, probe_type, None);
                match sender.send(&packet) {
                    Some(_r) => {
                        // TODO: Handle error
                    }
                    None => {}
                }
            }
            ProbeType::TcpEcnProbe => {
                let packet: Vec<u8> = builder::build_tcp_probe_packet(probe_setting, probe_type, None);
                match sender.send(&packet) {
                    Some(_r) => {
                        // TODO: Handle error
                    }
                    None => {}
                }
                tcp_syn_count -= 1;
                if tcp_syn_count > 0 {
                    thread::sleep(probe_setting.wait_time);
                    let ack_packet: Vec<u8> = builder::build_tcp_control_packet(probe_setting, TcpFlags::RST);
                    match sender.send(&ack_packet) {
                        Some(_r) => {
                            // TODO: Handle error
                        }
                        None => {}
                    }
                }
            }
        }
    }
}
