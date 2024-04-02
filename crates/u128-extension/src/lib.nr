trait U128Extension {
    fn to_le_bits(self) -> [u1; 128];
    fn from_le_bits(bits: [u1; 128]) -> Self;
    fn to_be_bits(self) -> [u1; 128];
    fn from_be_bits(bits: [u1; 128]) -> Self;
    fn from_be_bytes(bytes: [u8; 16]) -> Self;
    fn wrapping_sub(self, other: Self) -> Self;
    fn large_shr(self, n: U128) -> Self;
    fn div_without_overflow(self, other: Self) -> Self;
}

unconstrained fn unconstrained_div(a: U128, b: U128, b_carry: u64) -> (U128, U128) {
    // If b_carry is 1, then b is greater than 2^128 - 1 and 
    // thus greater than a
    if (b_carry > 0) | (a < b) {
        (U128::from_u64s_le(0, 0), a)
    } else {
        let mut carry = 0;
        let mut double_b = b;
        // (2^128 - 1) / 2 = 0x7fffffffffffffffffffffffffffffff
        // If b is above 0x7fffffffffffffffffffffffffffffff then
        // doubling it would overflow
        if b > U128::from_u64s_le(0xffffffffffffffff, 0x7fffffffffffffff) {
            carry = 1;
        } else {
            double_b *= U128::from_u64s_le(2, 0);
        }
        let (q,r) = unconstrained_div(a, double_b, carry);
        let q_mul_2 = q * U128::from_u64s_le(2, 0);
        if r < b {
            (q_mul_2, r)
        } else {
            (q_mul_2 + U128::from_u64s_le(1, 0), r - b)
        }
    }
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

    fn large_shr(self: U128, n: U128) -> U128 {
        assert(n < U128::from_u64s_le(128,0), "attempt to shift right with overflow");
        let exp_bits = n.lo.to_be_bits(7);

        let mut r: Field = 2;
        let mut y: Field = 1;
        for i in 1..8 {
            y = (exp_bits[7-i] as Field) * (r * y) + (1 - exp_bits[7-i] as Field) * y;
            r *= r;
        }
        self.div_without_overflow(U128::from_integer(y))
    }

    fn div_without_overflow(self: U128, other: U128) -> U128 {
        let (q,r) = unconstrained_div(self, other, 0);
        let a = other * q + r;
        assert(self == a);
        assert(r < other);
        q
    }
}
