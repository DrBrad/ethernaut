use std::sync::{Arc, Mutex};
use std::sync::mpsc::Sender;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};
use gtk::ListBox;
use gtk::prelude::{ContainerExt, SocketExtManual};
use pcap::{Capture, Device};
use crate::application::create_row;
use crate::packet::headers::ethernet_frame::EthernetFrame;
use crate::packet::headers::icmp_header::IcmpHeader;
use crate::packet::inter::ethernet_types::EthernetTypes;
use crate::packet::headers::ipv4_header::Ipv4Header;
use crate::packet::headers::tcp_header::TcpHeader;
use crate::packet::headers::udp_header::UdpHeader;
use crate::packet::inter::protocols::Protocols;
use crate::packet::packets::icmp_packet::IcmpPacket;
use crate::packet::packets::inter::packet_base::Packet;
use crate::packet::packets::tcp_packet::TcpPacket;
use crate::packet::packets::udp_packet::UdpPacket;
//use crate::PacketType;

pub fn packet_capture(tx: Arc<Mutex<Sender<Box<dyn Packet>>>>) {
    thread::spawn(move || {
        let devices = Device::list().expect("Failed to get device list");

        let device = devices.into_iter().find(|d| d.name.contains("wlp7s0"))
            .expect("No suitable device found");

        println!("Listening on device: {}", device.name);

        let mut cap = Capture::from_device(device)
            .expect("Failed to open device")
            .promisc(true)
            .immediate_mode(true)
            .open()
            .expect("Failed to start capture");

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis();

        while let Ok(packet) = cap.next_packet() {
            //println!("Captured packets: {:?} ({} bytes)", packets, packets.data.len());

            let ethernet_frame = EthernetFrame::from_bytes(packet.data).expect("Failed to parse Ethernet frame");
            //println!("{:?}", ethernet_frame.get_type());

            match ethernet_frame.get_type() {
                EthernetTypes::IPv4 => {
                    let ip_header = Ipv4Header::from_bytes(&packet.data[14..]).expect("Failed to parse IP header");
                    //tx.send(packets.header.ts, ip_header.source_ip, ip_header.destination_ip);
                    //println!("{:?} {} {}", ip_header.get_protocol(), ip_header.get_source_ip().to_string(), ip_header.get_destination_ip().to_string());

                    let time = get_timestamp(packet.header.ts.tv_sec as u32, packet.header.ts.tv_usec as u32)-now;

                    let packet = match ip_header.get_protocol() {
                        Protocols::Icmp => {
                            let header = IcmpHeader::from_bytes(&packet.data[34..]).expect("Failed to parse ICMP header");
                            IcmpPacket::from_bytes(ethernet_frame, ip_header, header, time, packet.len(), &packet.data[42..]).expect("Failed to parse ICMP packet").dyn_clone()
                        }
                        Protocols::Tcp => {
                            let header = TcpHeader::from_bytes(&packet.data[34..]).expect("Failed to parse TCP header");
                            TcpPacket::from_bytes(ethernet_frame, ip_header, header, time, packet.len(), &packet.data[54..]).expect("Failed to parse TCP packet").dyn_clone()
                        }
                        Protocols::Udp => {
                            let header = UdpHeader::from_bytes(&packet.data[34..]).expect("Failed to parse UDP header");
                            UdpPacket::from_bytes(ethernet_frame, ip_header, header, time, packet.len(), &packet.data[42..]).expect("Failed to parse UDP packet").dyn_clone()
                        }
                        _ => {
                            todo!()
                        }
                    };


                    tx.lock().unwrap().send(packet).expect("Failed to send packet");
                    /*

                    let packet = UdpPacket::from_bytes(ethernet_frame,
                                                       ip_header,
                                                       udp_header,
                                                       0,
                                                       packet.len(),
                                                       &packet.data[34..]).expect("Failed to parse UDP packet").dyn_clone();
                    tx.lock().unwrap().send(packet).expect("Failed to send packet");*/
                }
                EthernetTypes::Arp => {}
                EthernetTypes::IPv6 => {}
                _ => {}
            }



        }
    });
}

fn get_timestamp(ts_sec: u32, ts_usec: u32) -> u128 {
    (ts_sec as u128 * 1000) + (ts_usec as u128 / 1000)
}
