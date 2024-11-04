use k256::{ProjectivePoint, EncodedPoint, AffinePoint};
use k256::elliptic_curve::sec1::FromEncodedPoint;


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

// /// Converts a byte vector to a ProjectivePoint, assuming it is a compressed or uncompressed
// /// representation (33 or 65 bytes respectively). Returns None if the byte vector is invalid.
// pub fn bytes_to_projective_point(bytes: &Vec<u8>) -> Option<ProjectivePoint> {
//     // Try to parse the byte vector as an EncodedPoint
//     let encoded_point = EncodedPoint::from_bytes(bytes).ok()?;

//     // Convert the EncodedPoint to an AffinePoint, then convert AffinePoint to ProjectivePoint
//     AffinePoint::from_encoded_point(&encoded_point).map(Into::into).into()
// }


