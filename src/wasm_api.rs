use crate::protocol::{self, elgamal, frost, gg18, KeygenProtocol, ThresholdProtocol, ProtocolPayload};

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
#[repr(C)]
pub enum ProtocolId {
    Gg18,
    Elgamal,
    Frost,
}

fn into_wasm_result(result: protocol::Result<Vec<u8>>) -> Result<Box<[u8]>, String> {
    result
        .map(Vec::into_boxed_slice)
        .map_err(|err| err.to_string())
}

#[wasm_bindgen]
pub struct Protocol {
    // TODO: possible to avoid?
    instance: Box<dyn protocol::Protocol>,
}

#[wasm_bindgen]
impl Protocol {
    pub fn keygen(proto_id: ProtocolId) -> Self {
        Self {
            instance: match proto_id {
                ProtocolId::Gg18 => Box::new(gg18::KeygenContext::new()),
                ProtocolId::Elgamal => Box::new(elgamal::KeygenContext::new()),
                ProtocolId::Frost => Box::new(frost::KeygenContext::new()),
            },
        }
    }

    pub fn init(proto_id: ProtocolId, group: &[u8]) -> Self {
        Self {
            instance: match proto_id {
                ProtocolId::Gg18 => Box::new(gg18::SignContext::new(group)),
                ProtocolId::Elgamal => Box::new(elgamal::DecryptContext::new(group)),
                ProtocolId::Frost => Box::new(frost::SignContext::new(group)),
            },
        }
    }

    pub fn deserialize(ctx: &[u8]) -> Self {
        let payload: ProtocolPayload = serde_json::from_slice(ctx).unwrap();
        Self {
            instance: payload.boxed(),
        }
    }

    pub fn serialize(self) -> Box<[u8]> {
        let payload = self.instance.transport();
        serde_json::to_vec(&payload)
            .unwrap()
            .into_boxed_slice()
    }

    pub fn advance(&mut self, data: &[u8]) -> Result<Box<[u8]>, String> {
        into_wasm_result(self.instance.advance(data))
    }

    pub fn finish(self) -> Result<Box<[u8]>, String> {
        into_wasm_result(self.instance.finish())
    }
}

#[wasm_bindgen]
pub fn encrypt(msg: &[u8], key: &[u8]) -> Result<Box<[u8]>, String> {
    into_wasm_result(elgamal::encrypt(msg, key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn test_deserialize() {
        let proto = Protocol::keygen(ProtocolId::Gg18);
        let ser = proto.serialize();
        let proto2 = Protocol::deserialize(&ser);
    }
}
