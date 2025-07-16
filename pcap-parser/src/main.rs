mod cmdid;
mod packet;
mod error;
mod handler;

use pcap_file::pcap::PcapReader;
use std::fs::File;
use std::net::Ipv4Addr;
use byteorder::{BigEndian, ByteOrder};
use cmdid::{ScNetCmdID, CsNetCmdID};
use packet::{ClientPacket};
use clap::Parser;

#[derive(Parser)]
#[command(name = "pcap-parser")]
#[command(about = "Parse Reverse:1999 TCP PCAP dump", long_about = None)]
struct Args {
    #[arg(short, long)]
    file: String,
}

const SERVER_IP: Ipv4Addr = Ipv4Addr::new(43, 175, 235, 39);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let file = File::open(&args.file)?;
    let mut pcap = PcapReader::new(file)?;

    let loaded = format!("[+] Loaded packets from {}", args.file);
    println!("{}", loaded);

    for (i, pkt_result) in pcap.by_ref().enumerate() {
        let pkt = pkt_result?;
        let data = pkt.data;

        if data.len() < 54 {
            continue;
        }

        let src_ip = Ipv4Addr::new(data[26], data[27], data[28], data[29]);
        let dst_ip = Ipv4Addr::new(data[30], data[31], data[32], data[33]);

        let ip_header_len = (data[14] & 0x0F) * 4;
        let tcp_header_start = 14 + ip_header_len as usize;
        let tcp_header_len = ((data[tcp_header_start + 12] >> 4) & 0xF) * 4;

        let payload_start = tcp_header_start + tcp_header_len as usize;
        if payload_start >= data.len() {
            continue;
        }

        let payload = &data[payload_start..];

        if payload.len() < 11 {
            continue;
        }

        let direction = if src_ip == SERVER_IP { "←" } else { "→" };
        let is_client = src_ip != SERVER_IP;

        let sport = u16::from_be_bytes([data[tcp_header_start], data[tcp_header_start + 1]]);
        let dport = u16::from_be_bytes([data[tcp_header_start + 2], data[tcp_header_start + 3]]);

        if sport != 12004 && dport != 12004 {
            continue;
        }
        
        println!(
            "[{i:04}] TCP from {src_ip}:{sport} {direction} {dst_ip}:{dport}, len={}",
            payload.len()
        );
        println!("       {:02x?}", &payload[..32.min(payload.len())]);


        if is_client {
            match ClientPacket::decode_all(payload) {
                Ok(pkts) => {
                    for pkt in pkts {
                        let cmd_id_raw = pkt.cmd_id;
                        let seq = pkt.sequence;
                        let up_tag = pkt.up_tag;

                        match CsNetCmdID::try_from(cmd_id_raw as i32) {
                            Ok(cmd_id) => {
                                println!(
                                    "       [Client] [{cmd_id:?}] cmdId={cmd_id_raw}, seq={seq}, upTag={up_tag}, dataLen={}",
                                    pkt.data.len()
                                );
                                handler::dispatch_client_packet(cmd_id, &pkt);
                            }
                            Err(_) => {
                                println!(
                                    "       [Client] cmdId={cmd_id_raw}, seq={seq}, upTag={up_tag}, dataLen={}",
                                    pkt.data.len()
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    println!("       [Client] × Failed to decode packet(s): {e}");
                }
            }
        }
        else {
            if payload.len() >= 10 {
                let cmd_id_raw = BigEndian::read_i16(&payload[4..6]);
                let result = BigEndian::read_i16(&payload[6..8]);
                let up_tag = payload[8];
                let down_tag = payload[9];
                let data = &payload[10..];

                match ScNetCmdID::try_from(cmd_id_raw as i32) {
                    Ok(cmd_id) => {
                        println!(
                            "       [Server] [{cmd_id:?}] cmdId={cmd_id_raw}, result={result}, upTag={up_tag}, downTag={down_tag}, dataLen={}",
                            data.len()
                        );
                        handler::dispatch_server_packet(cmd_id, data);
                    }
                    Err(_) => {
                        println!(
                            "       [Server] cmdId={cmd_id_raw}, result={result}, upTag={up_tag}, downTag={down_tag}, dataLen={}",
                            data.len()
                        );
                    }
                }
            }
        }


    }

    Ok(())
}