use crate::cmdid::{CsNetCmdID,ScNetCmdID};
use crate::packet::ClientPacket;
use sonettobuf::*;
use std::str;
use byteorder::{BigEndian, ByteOrder};

macro_rules! json_info_handler {
    ($pkt:ident, $msg_type:ty) => {{
        match $pkt.decode_message::<$msg_type>() {
            Ok(msg) => {
                println!("       → Parsed {}:", stringify!($msg_type));
                if let Some(info_json_str) = &msg.info {
                    match serde_json::from_str::<serde_json::Value>(info_json_str) {
                        Ok(json_val) => {
                            println!("{}", serde_json::to_string_pretty(&json_val).unwrap());
                        }
                        Err(e) => {
                            println!("       × Failed to parse `info` as JSON: {e}");
                            println!("       → Raw info string: {info_json_str}");
                        }
                    }
                } else {
                    println!("       → No info field present.");
                }
            }
            Err(e) => {
                println!("       × Failed to decode {}: {e}", stringify!($msg_type));
            }
        }
    }};
}

macro_rules! default_proto_handler {
    ($data:expr, $msg_type:ty) => {{
        let bytes: &[u8] = &$data;
        let mut buf = bytes;
        match <$msg_type as prost::Message>::decode(&mut buf) {
            Ok(msg) => println!("       → Parsed {}: {:#?}", stringify!($msg_type), msg),
            Err(e) => println!("       × Failed to decode {}: {e}", stringify!($msg_type)),
        }
    }};
}

pub fn dispatch_client_packet(cmd_id: CsNetCmdID, pkt: &ClientPacket) {
    match cmd_id {
        CsNetCmdID::LoginRequest => handle_login_request(pkt),

        CsNetCmdID::UpdateClientStatBaseInfoRequest => json_info_handler!(pkt, UpdateClientStatBaseInfoRequest),
        CsNetCmdID::ClientStatBaseInfoRequest => json_info_handler!(pkt, ClientStatBaseInfoRequest),
        CsNetCmdID::GetServerTimeRequest => default_proto_handler!(pkt.data, GetServerTimeRequest),
        CsNetCmdID::GetPlayerInfoRequest => default_proto_handler!(pkt.data, GetPlayerInfoRequest),
        CsNetCmdID::GetGuideInfoRequest => default_proto_handler!(pkt.data, GetGuideInfoRequest),
        CsNetCmdID::GetSimplePropertyRequest => default_proto_handler!(pkt.data, GetSimplePropertyRequest),
        CsNetCmdID::GetCurrencyListRequest => default_proto_handler!(pkt.data, GetCurrencyListRequest),
        CsNetCmdID::Act160GetInfoRequest => default_proto_handler!(pkt.data, Act160GetInfoRequest),
        CsNetCmdID::GetClothInfoRequest => default_proto_handler!(pkt.data, GetClothInfoRequest),
        CsNetCmdID::HeroInfoListRequest => default_proto_handler!(pkt.data, HeroInfoListRequest),
        CsNetCmdID::GetHeroGroupListRequest => default_proto_handler!(pkt.data, GetHeroGroupListRequest),
        CsNetCmdID::GetItemListRequest => default_proto_handler!(pkt.data, GetItemListRequest),
        CsNetCmdID::GetDungeonRequest => default_proto_handler!(pkt.data, GetDungeonRequest),
        CsNetCmdID::ReconnectFightRequest => default_proto_handler!(pkt.data, ReconnectFightRequest),
        CsNetCmdID::GetBuyPowerInfoRequest => default_proto_handler!(pkt.data, GetBuyPowerInfoRequest),
        CsNetCmdID::GetEquipInfoRequest => default_proto_handler!(pkt.data, GetEquipInfoRequest),
        CsNetCmdID::GetStoryRequest => default_proto_handler!(pkt.data, GetStoryRequest),
        CsNetCmdID::GetChargeInfoRequest => default_proto_handler!(pkt.data, GetChargeInfoRequest),
        CsNetCmdID::GetMonthCardInfoRequest => default_proto_handler!(pkt.data, GetMonthCardInfoRequest),
        _ => {
            println!(
                "       → [Unimplemented] No handler for {:?} (cmdId={})",
                cmd_id, pkt.cmd_id
            );
        }
    }

}


pub fn dispatch_server_packet(
    cmd_id: ScNetCmdID,
    data: &[u8],
) {
    match cmd_id {
        ScNetCmdID::LoginReply => {
            if data.len() >= 8 {
                let user_id = BigEndian::read_i64(&data[0..8]);
                let msg = LoginReply { user_id };
                println!("       → Parsed LoginReply: {:?}", msg);
            } else {
                println!("       × LoginReply data too short");
            }
        },
        ScNetCmdID::UpdateRedDotPush => default_proto_handler!(data, UpdateRedDotPush),
        ScNetCmdID::CritterInfoPush => default_proto_handler!(data, CritterInfoPush),
        ScNetCmdID::StatInfoPush => default_proto_handler!(data, StatInfoPush),
        ScNetCmdID::GetServerTimeReply => default_proto_handler!(data, GetServerTimeReply),
        ScNetCmdID::GetPlayerInfoReply => default_proto_handler!(data, GetPlayerInfoReply),
        ScNetCmdID::GetCurrencyListReply => default_proto_handler!(data, GetCurrencyListReply),
        ScNetCmdID::GetGuideInfoReply => default_proto_handler!(data, GetGuideInfoReply),
        ScNetCmdID::EndActivityPush => default_proto_handler!(data, EndActivityPush),
        _ => {
            println!(
                "       → [Unimplemented] No handler for {:?} ",
                cmd_id
            );
        }
    }
}

fn handle_login_request(pkt: &ClientPacket) {
    println!(
        "       → [LoginRequest Handler] dataLen={}, raw={:02x?}",
        pkt.data.len(),
        &pkt.data[..pkt.data.len().min(16)]
    );

    if let Ok(raw_str) = str::from_utf8(&pkt.data) {
        let cleaned = raw_str.trim_matches(|c: char| c == '\0' || c.is_control());
        println!("       → LoginRequest string: {}", cleaned);

        if let Some((account_id, uuid)) = cleaned.split_once('$') {
            let msg = LoginRequest {
                account_id: account_id.trim_matches(char::from(0)).to_string(),
                uuid: uuid.trim_matches(char::from(0)).to_string(),
            };
            println!("       → Parsed LoginRequest: {:?}", msg);
        } else {
            println!("       × Failed to split LoginRequest string");
        }
    } else {
        println!("       × LoginRequest not valid UTF-8");
    }
}
