trait U128Extension {
    fn to_le_bits(self) -> [u1; 128];
    fn from_le_bits(bits: [u1; 128]) -> Self;
    fn to_be_bits(self) -> [u1; 128];
    fn from_be_bits(bits: [u1; 128]) -> Self;
    fn from_be_bytes(bytes: [u8; 16]) -> Self;
    fn wrapping_sub(self, other: Self) -> Self;
    fn large_shr(self, n: u64) -> Self;
}

fn reverse_bytes_array(array: [u8; 16]) -> [u8; 16] {
    let mut reversed = [0; 16];
    for i in 0..16 {
        reversed[i] = array[15 - i];
    }
    reversed
}

impl U128Extension for U128 {
    fn to_le_bits(self: U128) -> [u1; 128] {
        let mut res: [u1; 128] = [0; 128];
        let bytes = self.to_le_bytes();
    
        for i in 0..16 {
            let bits = (bytes[i] as Field).to_le_bits(8);
            for j in 0..8 {
                let idx = i as Field * (8 as Field) + (j as Field);
                res[idx] = bits[j as Field];
            }
        }
    
        res
    }

    fn from_le_bits(bits: [u1; 128]) -> U128 {
        let mut bytes = [0 as u8; 16];
        for i in 0..128 {
            let byte_index = i / 8;
            let bit_index = i % 8;
            bytes[byte_index] |= bits[i] as u8 << bit_index as u8;
        }
        U128::from_le_bytes(bytes)
    }

    fn to_be_bits(self: U128) -> [u1; 128] {
        let mut res: [u1; 128] = [0; 128];
        let bytes = self.to_be_bytes();
    
        for i in 0..16 {
            let bits = (bytes[i] as Field).to_be_bits(8);
            for j in 0..8 {
                let idx = i as Field * (8 as Field) + (j as Field);
                res[idx] = bits[j as Field];
            }
        }
    
        res
    }

    fn from_be_bytes(bytes: [u8; 16]) -> U128 {
        let res = U128::from_le_bytes(reverse_bytes_array(bytes));
        res
    }

    fn from_be_bits(bits: [u1; 128]) -> U128 {
        let mut bytes = [0 as u8; 16];
        for i in 0..128 {
            let byte_index = i / 8;
            let bit_index = i % 8;
            bytes[byte_index] |= bits[i] as u8 << (7 - bit_index) as u8;
        }
        U128::from_be_bytes(bytes)
    }

    fn wrapping_sub(self: U128, other: U128) -> U128 {
        let max = U128::from_hex("0xffffffffffffffffffffffffffffffff");
        if self < other {
            let diff = other - self;
            max - diff + U128::from_integer(1)
        } else {
            self - other
        }
    }

    fn large_shr(self: U128, n: u64) -> U128 {
        let mut res = self;
        let max = U128::from_hex("0x0fffffffffffffffffffffffffffffff");
        // Switch to a different implementation if n is too large
        // as the default implementation for right shift for U128
        // will trigger an overflow for number too close to 2^128
        // It's less efficient to do this, so for smaller number
        // we still use the default implementation
        if res >= max {
            let bits = res.to_be_bits();
            let mut new_bits = [0; 128];
            for i in 0..128 {
                if i < n {
                    new_bits[i] = 0;
                } else {
                    new_bits[i] = bits[i - n];
                }
            }
            res = U128::from_be_bits(new_bits);
        } else {
            let n = U128::from_integer(n);
            res = res >> n;
        }
        res
    }
}
