use crate::MyReader;

#[derive(Debug)]
pub struct SignatureSchemeV3 {
    size: usize,
    id: u32,
    data: Vec<u8>,
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
