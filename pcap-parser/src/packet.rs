use crate::error::{AppError, PacketError};
use byteorder::{BE, ByteOrder};
use sonettobuf::prost::Message;

#[derive(Debug)]
pub struct ServerPacket {
    pub cmd_id: i16,
    pub result_code: i16,
    pub up_tag: u8,
    pub down_tag: u8,
    pub data: Vec<u8>,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct ClientPacket {
    pub sequence: i32,
    pub cmd_id: i16,
    pub up_tag: u8,
    pub data: Vec<u8>,
}

#[allow(dead_code)]
impl ServerPacket {
    const PACKET_HEADER: usize = 10;

    pub fn encode(&self) -> Vec<u8> {
        let total_len = Self::PACKET_HEADER + self.data.len();
        let mut buffer = vec![0u8; total_len];

        BE::write_u32(&mut buffer[0..4], (total_len - 4) as u32);
        BE::write_i16(&mut buffer[4..6], self.cmd_id);
        BE::write_i16(&mut buffer[6..8], self.result_code);
        buffer[8] = self.up_tag;
        buffer[9] = self.down_tag;
        buffer[Self::PACKET_HEADER..].copy_from_slice(&self.data);

        buffer
    }

    pub fn decode(buffer: &[u8]) -> Result<Self, AppError> {
        if buffer.len() < Self::PACKET_HEADER {
            return Err(AppError::Packet(PacketError::LengthLessThanHeader(
                Self::PACKET_HEADER,
                buffer.len(),
            )));
        }

        let packet_size = BE::read_u32(&buffer[0..4]) as usize;
        if buffer.len() < packet_size + 4 {
            return Err(AppError::Packet(PacketError::LengthMismatch(
                packet_size + 4,
                buffer.len(),
            )));
        }

        let cmd_id = BE::read_i16(&buffer[4..6]);
        let result_code = BE::read_i16(&buffer[6..8]);
        let up_tag = buffer[8];
        let down_tag = buffer[9];
        let data = buffer[Self::PACKET_HEADER..packet_size + 4].to_vec();

        Ok(Self {
            cmd_id,
            result_code,
            up_tag,
            down_tag,
            data,
        })
    }


    pub fn decode_message<T: Message + Default>(&self) -> Result<T, AppError> {
        T::decode(&*self.data)
            .map_err(|e| AppError::Packet(PacketError::ServerPacketDataDecodeFail(e)))
    }
}

#[allow(dead_code)]
impl ClientPacket {
    const PACKET_HEADER: usize = 11;

    pub fn decode(buffer: &[u8]) -> Result<Self, AppError> {
        if buffer.len() < Self::PACKET_HEADER {
            return Err(AppError::Packet(PacketError::LengthLessThanHeader(
                Self::PACKET_HEADER,
                buffer.len(),
            )));
        }

        let packet_size = BE::read_i32(&buffer[0..4]) as usize;

        if buffer.len() != packet_size + 4 {
            return Err(AppError::Packet(PacketError::LengthMismatch(
                packet_size + 4,
                buffer.len(),
            )));
        }

        let sequence = BE::read_i32(&buffer[4..8]);
        let cmd_id = BE::read_i16(&buffer[8..10]);
        let up_tag = buffer[10];
        let data = buffer[Self::PACKET_HEADER..].to_vec();

        Ok(Self {
            sequence,
            cmd_id,
            up_tag,
            data,
        })
    }

    pub fn decode_all(mut buffer: &[u8]) -> Result<Vec<ClientPacket>, AppError> {
        let mut packets = Vec::new();

        while buffer.len() >= ClientPacket::PACKET_HEADER {
            let packet_size = BE::read_u32(&buffer[0..4]) as usize;

            // Full packet length = header (4) + declared size
            let total_len = packet_size + 4;
            if buffer.len() < total_len {
                break; // wait for more data (incomplete packet)
            }

            let sequence = BE::read_i32(&buffer[4..8]);
            let cmd_id = BE::read_i16(&buffer[8..10]);
            let up_tag = buffer[10];
            let data = buffer[11..total_len].to_vec();

            packets.push(ClientPacket {
                sequence,
                cmd_id,
                up_tag,
                data,
            });

            buffer = &buffer[total_len..];
        }

        Ok(packets)
    }


    pub fn decode_message<T: Message + Default>(&self) -> Result<T, AppError> {
        let data = &*self.data;
        let decoded = T::decode(data)
            .map_err(|e| AppError::Packet(PacketError::ClientPacketDataDecodeFail(e)))?;
        Ok(decoded)
    }
}
