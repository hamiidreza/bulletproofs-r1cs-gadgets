extern crate byteorder;
extern crate rand;
extern crate curve25519_dalek;

use rand::SeedableRng;
use rand::rngs::OsRng;
use curve25519_dalek::scalar::Scalar;
use std::fmt;
pub type ScalarBytes = [u8; 32];

pub const TreeDepth: usize = 253;

/// Get a 253 elem bit array of this scalar, LSB is first element of this array
#[derive(Copy, Clone)]
pub struct ScalarBits {
    bit_array: [i8; TreeDepth]
}

impl fmt::Debug for ScalarBits {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.bit_array.to_vec())
    }
}

impl ScalarBits {
    pub fn from_scalar(scalar: &Scalar) -> Self {
        let s = scalar.reduce();
        let b = get_bits(&s);
        for i in TreeDepth..256 {
            assert_eq!(b[i], 0);
        }

        let mut reduced_bits = [0; TreeDepth];
        for i in 0..TreeDepth {
            reduced_bits[i] = b[i];
        }
        Self {
            bit_array: reduced_bits
        }
    }

    pub fn from_scalar_dont_reduce(scalar: &Scalar) -> Self {
        //let s = scalar.reduce();
        let b = get_bits(scalar);
        for i in TreeDepth..256 {
            assert_eq!(b[i], 0);
        }

        let mut reduced_bits = [0; TreeDepth];
        for i in 0..TreeDepth {
            reduced_bits[i] = b[i];
        }
        Self {
            bit_array: reduced_bits
        }
    }

    pub fn to_scalar(&self) -> Scalar {
        /*let mut bytes: [u8; 32] = [0; 32];
        let powers_of_2: [u8; 8] = [1, 2, 4, 8, 16, 32, 64, 128];
        let mut i = 0;
        let mut current_byte = 0u8;
        for b in self.bit_array.iter() {
            if *b == 1 {
                current_byte += powers_of_2[i % 8];
            }
            i += 1;
            if (i % 8) == 0 {
                bytes[(i / 8) -1] = current_byte;
                current_byte = 0;
            }
        }
        bytes[31] = current_byte;
        Scalar::from_bits(bytes).reduce()*/
        self.to_non_reduced_scalar().reduce()
    }

    pub fn to_non_reduced_scalar(&self) -> Scalar {
        let mut bytes: [u8; 32] = [0; 32];
        let powers_of_2: [u8; 8] = [1, 2, 4, 8, 16, 32, 64, 128];
        let mut i = 0;
        let mut current_byte = 0u8;
        for b in self.bit_array.iter() {
            if *b == 1 {
                current_byte += powers_of_2[i % 8];
            }
            i += 1;
            if (i % 8) == 0 {
                bytes[(i / 8) -1] = current_byte;
                current_byte = 0;
            }
        }
        bytes[31] = current_byte;
        Scalar::from_bits(bytes)
    }

    /// Shift left by 1 bit
    pub fn shl(&mut self) {
        for i in (1..TreeDepth).rev() {
            self.bit_array[i] = self.bit_array[i-1];
        }
        self.bit_array[0] = 0;
    }

    /// Shift right by 1 bit
    pub fn shr(&mut self) {
        for i in 1..TreeDepth {
            self.bit_array[i-1] = self.bit_array[i];
        }
        self.bit_array[TreeDepth-1] = 0;
    }

    /// Return a new bit-array shifted to the left with 1 bit
    pub fn new_left_shifted(&self) -> Self {
        // Not using the above method `shl` to avoid copying
        let mut new_array = [0; TreeDepth];
        for i in (1..TreeDepth).rev() {
            new_array[i] = self.bit_array[i-1];
        }
        new_array[0] = 0;
        Self {
            bit_array: new_array
        }
    }

    /// Return a new bit-array shifted to the right with 1 bit
    pub fn new_right_shifted(&self) -> Self {
        // Not using the above method `shr` to avoid copying
        let mut new_array = [0; TreeDepth];
        for i in 1..TreeDepth {
            new_array[i-1] = self.bit_array[i];
        }
        new_array[TreeDepth-1] = 0;
        Self {
            bit_array: new_array
        }
    }

    /// Check if most significant bit is set
    pub fn is_msb_set(&self) -> bool {
        self.bit_array[TreeDepth-1] == 1
    }

    /// Check if least significant bit is set
    pub fn is_lsb_set(&self) -> bool {
        self.bit_array[0] == 1
    }
}

pub fn get_bits(scalar: &Scalar) -> [i8; 256] {
    let mut bits = [0i8; 256];
    let bytes = scalar.as_bytes();
    for i in 0..256 {
        // As i runs from 0..256, the bottom 3 bits index the bit,
        // while the upper bits index the byte.
        bits[i] = ((bytes[i>>3] >> (i&7)) & 1u8) as i8;
    }
    bits
}

pub fn scalar_to_u64_array(scalar: &Scalar) -> [u64; 4] {
    use self::byteorder::{ByteOrder, LittleEndian};
    let bytes = scalar.to_bytes();
    let mut result = [0; 4];
    LittleEndian::read_u64_into(&bytes, &mut result);
    result
}

pub fn u64_array_to_scalar(array: &[u64; 4]) -> Scalar {
    use self::byteorder::{ByteOrder, LittleEndian};
    let mut result: [u8; 32] = [0; 32];
    LittleEndian::write_u64_into(array, &mut result);
    let s = Scalar::from_bits(result);
    s.reduce()
}


#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::BASEPOINT_ORDER;

    #[test]
    fn test_shl_shr() {
        let mut csprng: OsRng = OsRng::new().unwrap();
        for _ in 0..100 {
            let r: Scalar = Scalar::random(&mut csprng);
            let mut b_arr = ScalarBits::from_scalar(&r);
            assert_eq!(r, b_arr.to_scalar());
        }

        /*let mut one = ScalarBitArray::from_scalar(&Scalar::one());
        println!("{:?}", one.to_scalar());
        for i in 0..TreeDepth {
            one.shl();
            println!("i={}, {:?}", i, one.to_scalar());
        }*/
    }

    #[test]
    fn test_scalar_to_u64_array() {
        for n in vec![32, 255, 127, 488, 256, 257].iter() {
            let s = Scalar::from(*n as u64);
            let u = scalar_to_u64_array(&s);
            let e = u64_array_to_scalar(&u);
            assert_eq!(e, s);
            /*println!("{:?}", u);
            println!("{:?}", e);*/
        }

        let o = BASEPOINT_ORDER - Scalar::one();
        let u = scalar_to_u64_array(&o);
        let e = u64_array_to_scalar(&u);
        assert_eq!(e, o);

        {
            let u: [u64; 4] = [0, 0, 0, 1762596304162127872];
            let s = u64_array_to_scalar(&u);
            println!("s={:?}", s);
            let b = ScalarBits::from_scalar(&s);
            println!("b={:?}", b);
            let s1 = b.to_scalar();
            println!("s1={:?}", s1);
            let u1 = scalar_to_u64_array(&s1);
            println!("u1={:?}", u1);
        }
    }
}