use k256::{ProjectivePoint, EncodedPoint, AffinePoint};
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::Scalar;

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

/// Converts a byte vector to a ProjectivePoint, assuming it is a compressed or uncompressed
/// representation (33 or 65 bytes respectively). Returns None if the byte vector is invalid.
pub fn bytes_to_projective_point(bytes: &Vec<u8>) -> Option<ProjectivePoint> {
    // Try to parse the byte vector as an EncodedPoint
    let encoded_point = EncodedPoint::from_bytes(bytes).ok()?;

    // Convert the EncodedPoint to an AffinePoint, then convert AffinePoint to ProjectivePoint
    AffinePoint::from_encoded_point(&encoded_point).map(Into::into).into()
}


#[cfg(test)]
mod tests {
    use super::*;
    use k256::{ProjectivePoint, EncodedPoint};

    #[test]
    fn test_projective_point_to_bytes() {
        // Generate an example projective point using the generator point
        let original_point = ProjectivePoint::GENERATOR;

        // Convert the projective point to bytes
        let encoded_point: EncodedPoint = original_point.to_affine().into();
        let bytes = encoded_point.as_bytes();

        // Convert bytes back to a ProjectivePoint
        let reconstructed_point = bytes_to_projective_point(&bytes.to_vec())
            .expect("Failed to convert bytes back to ProjectivePoint");

        // Verify that the original point and the reconstructed point are equal
        assert_eq!(original_point, reconstructed_point);
    }
}
