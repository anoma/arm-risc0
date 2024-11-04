

/// Converts a Vec<u8> to a [u8; 32] array if the Vec has exactly 32 bytes.
/// Returns None if the Vec length is not 32.
pub fn vec_to_array(bytes: Vec<u8>) -> Option<[u8; 32]> {
    if bytes.len() == 32 {
        // Convert Vec<u8> to [u8; 32]
        let array: [u8; 32] = bytes.try_into().ok()?;
        Some(array)
    } else {
        None // Return None if the length is not 32
    }
}




