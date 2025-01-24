use crate::MyReader;

#[derive(Debug)]
pub struct SignatureSchemeV3 {
    pub size: usize,
    pub id: u32,
    pub data: Vec<u8>,
}

impl SignatureSchemeV3 {
    pub fn new(size: usize, id: u32, data: &mut MyReader) -> Self {
        Self {
            size,
            id,
            data: data.to_vec(),
        }
    }
}
