use dep::std::println;
use dep::std::bigint::{BigInt, Secpk1Fq};
use dep::std::ops::{Add, Sub, Mul, Div, Rem, BitOr, BitAnd, BitXor, Shl, Shr};
use dep::std::cmp::{Eq, Ord, Ordering};
use dep::u128_extension::{U128Extension};

mod utils;

// NOTE: this file is forked from https://github.com/SetProtocol/noir-rsa
// NOTE: this file is forked from https://github.com/shuklaayush/noir-bigint v0.1.0

// Top-level constants related to the size of LargeInteger limbs and bytes.
global NUM_LIMBS: u64  = 96; /// Number of limbs.
global BITS_PER_LIMB: u64  = 64; /// Number of bits per limb.
global BYTES_PER_LIMB: u64  = 8; /// Number of bytes per limb (BITS_PER_LIMB / 8).
global MAX_BITS: u64 = 6144; /// Maximum number of bits (NUM_LIMBS * BITS_PER_LIMB).
global MAX_BYTES: u64  = 768; /// Maximum number of bytes (NUM_LIMBS * BYTES_PER_LIMB).

struct LargeInteger {
    limbs: [u64; NUM_LIMBS],
}

impl LargeInteger {
    /// Creates a new LargeInteger initialized to zero.
    pub fn zero() -> Self {
        Self { limbs: [0; NUM_LIMBS] }
    }

    /// Creates a new LargeInteger initialized to one.
    pub fn one() -> Self {
        let mut one = LargeInteger::zero();
        one.limbs[0] = 1;
        one
    }
    
    /// Constructs a LargeInteger from a single `u64` value.
    pub fn from_integer(val: u64) -> Self {
        let mut buint = LargeInteger::zero();
        buint.limbs[0] = val;
        buint
    }

    fn to_integer(self: Self) -> u64 {
        // Assume the other limbs are empty
        self.limbs[0]
    }
 
    /// Constructs a LargeInteger from a byte array in little-endian format.
    pub fn from_bytes<B>(bytes: [u8; B]) -> Self {
        let mut res = LargeInteger::zero();
        for i in 0..bytes.len() {
            let limb_index = (i as u64) / (BYTES_PER_LIMB as u64);
            let byte_index = (i as u64) % (BYTES_PER_LIMB as u64);

            res.limbs[limb_index as Field] |= (bytes[i] as u64) << (byte_index * 8) as u8; // casted to u8. Might break.
        }

        res
    }

    /// Returns the little-endian byte array representation of the LargeInteger.
    fn to_bytes(self: Self) -> [u8; MAX_BYTES] {
        let mut res = [0 as u8; MAX_BYTES];
    
        for i in 0..NUM_LIMBS {
            let limb_bytes = (self.limbs[i] as Field).to_le_bytes(BYTES_PER_LIMB as u32);
            for j in 0..BYTES_PER_LIMB {
                let idx = i * BYTES_PER_LIMB + j;
                res[idx] = limb_bytes[j];
            }
        }
    
        res
    }

    /// Returns the bit array representation of the LargeInteger, with LSB at index 0.
    fn to_bits(self: Self) -> [u1; MAX_BITS] {
        let mut res = [0 as u1; MAX_BITS];
    
        for i in 0..NUM_LIMBS {
            let limb_bits = (self.limbs[i] as Field).to_le_bits(BITS_PER_LIMB as u32);
            for j in 0..BITS_PER_LIMB {
                let idx = i * BITS_PER_LIMB + j;
                res[idx] = limb_bits[j];
            }
        }
    
        res
    }

    /// Adds two LargeInteger numbers with carry.
    /// Returns a tuple containing the result and the carry.
    fn adc(self: Self, other: Self) -> (Self, u64) {
        let mut res = LargeInteger::zero();
        let mut carry = 0 as u64;

        for i in 0..NUM_LIMBS {
            let (sum, new_carry) = utils::adc(self.limbs[i], other.limbs[i], carry);
            res.limbs[i] = sum;
            carry = new_carry;
        };

        (res, carry)
    }

    /// Adds two LargeInteger instances without returning the carry.
    fn add(self: Self, other: Self) -> Self {
        let (res, _carry) = self.adc(other);
        assert(_carry == 0);
        res
    }

    /// Subtracts two LargeInteger numbers with borrow.
    /// Returns a tuple containing the result and the borrow.
    fn sbb(self: Self, other: Self) -> (Self, u64) {
        let mut res = LargeInteger::zero();
        let mut borrow = 0;

        for i in 0..NUM_LIMBS {
            let (diff, new_borrow) = utils::sbb(self.limbs[i], other.limbs[i], borrow);
            res.limbs[i] = diff;
            borrow = new_borrow;
        };
        
        (res, borrow)
    }

    /// Subtracts two LargeInteger instances without returning the borrow.
    fn sub(self: Self, other: Self) -> Self {
        let (res, _borrow) = self.sbb(other);
        assert(_borrow == 0);
        res
    }

    /// Multiplies two LargeInteger instances using long multiplication.
    /// Returns a tuple containing the lower and higher parts of the multiplication result.
    fn mul(self: Self, other: Self) -> (Self, Self) {
        let mut lo = LargeInteger::zero();
        let mut hi = LargeInteger::zero();

        for i in 0..NUM_LIMBS {
            let mut carry = 0;

            for j in 0..NUM_LIMBS {
                let k = i + j;

                if k as u64 >= NUM_LIMBS as u64 {
                    let (n, c) = utils::mac(hi.limbs[k - NUM_LIMBS], self.limbs[i], other.limbs[j], carry);
                    hi.limbs[k - NUM_LIMBS] = n;
                    carry = c;
                } else {
                    let (n, c) = utils::mac(lo.limbs[k], self.limbs[i], other.limbs[j], carry);
                    lo.limbs[k] = n;
                    carry = c;
                }
            };

            hi.limbs[i] = carry;
        };

        (lo, hi)
    }

    /// Shifts the LargeInteger instance to the left by a specified number of bits `n`.
    /// where `0 <= n < Limb::BITS`,
    /// Returns the shifted result and the carry.
    fn shl_limb(self: Self, n: u64) -> (Self, u64) {
        assert(n < BITS_PER_LIMB as u64);

        let mut res = self;

        let rshift = BITS_PER_LIMB as u64 - n;
        let carry = if (n == 0) { 0 } else { self.limbs[NUM_LIMBS - 1] >> rshift as u8 }; // casted to u8, might break

        if (n > 0) {
            res.limbs[0] = self.limbs[0] << n as u8; // casted to u8, might break
            for i in 1..NUM_LIMBS {
                res.limbs[i] = (self.limbs[i] << n as u8) | (self.limbs[i - 1] >> rshift as u8); // casted to u8, might break
            }
        }

        (res, carry)
    }

    /// Shifts the LargeInteger instance to the left by 1 bit.
    fn shl1(self: Self) -> Self {
        let (res, _carry) = self.shl_limb(1);
        res
    }

    /// Shifts the LargeInteger instance to the left by a specified number of bits `n`.
    fn shl(self: Self, n: u64) -> Self {
        let mut res = LargeInteger::zero();

        if n < MAX_BITS as u64 {
            let shift_num = n / (BITS_PER_LIMB as u64);
            let rem = n % (BITS_PER_LIMB as u64);
            
            for i in shift_num..NUM_LIMBS {
                //if i as u64 >= shift_num {
                res.limbs[i as u64] = self.limbs[i as u64 - shift_num];
                //}
            }

            let (new_lower, _carry) = res.shl_limb(rem);
            res = new_lower;
        }

        res
    }

    /// Shifts the LargeInteger instance to the right by a specified number of bits `n`.
    /// where `0 <= n < Limb::BITS`,
    fn shr_limb(self: Self, n: u64) -> Self {
        assert(n < BITS_PER_LIMB as u64);

        let mut res = self;

        if (n > 0) {
            let lshift = BITS_PER_LIMB as u64 - n;

            for i in 0..NUM_LIMBS-1 {
                res.limbs[i] = (self.limbs[i] >> n as u8) | (self.limbs[i + 1] << lshift as u8); // casted to u8, might break
            }
            res.limbs[NUM_LIMBS - 1] = self.limbs[NUM_LIMBS - 1] >> n as u8; // casted to u8, might break
        }


        res
    }

    /// Shifts the LargeInteger instance to the right by 1 bit.
    fn shr1(self: Self) -> Self {
        let res = self.shr_limb(1);
        res
    }

    /// Shifts the LargeInteger instance to the right by a specified number of bits.
    fn shr(self: Self, n: u64) -> Self {
        let mut res = LargeInteger::zero();

        if n < MAX_BITS as u64 {
            let shift_num = n / (BITS_PER_LIMB as u64);
            let rem = n % (BITS_PER_LIMB as u64);

            // for i in 0..shift_num {
            for i in 0..NUM_LIMBS {
                if i as u64 + shift_num < NUM_LIMBS as u64 {
                    res.limbs[i] = self.limbs[i as Field + shift_num as Field];
                }
            }

            res = res.shr_limb(rem);
        }

        res
    }

    /// Returns the number of bits needed to represent the LargeInteger instance.
    fn nbits(self: Self) -> u64 {
        let bits = LargeInteger::to_bits(self);
        let mut res = 0;
        let mut done = false;
        for i in 0..MAX_BITS {
            if !done {
                if bits[MAX_BITS - i - 1] != 0 {
                    res = (MAX_BITS - i - 1) as u64 + 1;
                    done = true;
                }
            }
        }

        res
    }

    // Returns the number of non-zero limbs needed to represent the LargeInteger instance.
    fn nlimbs(self: Self) -> u64 {
        let mut res = 0;
        let mut done = false;
        for i in 0..NUM_LIMBS {
            if !done {
                if self.limbs[NUM_LIMBS - i - 1] != 0 {
                    res = (NUM_LIMBS - i - 1) as u64 + 1;
                    done = true;
                }
            }
        }

        res
    }


    /// Divides the LargeInteger instance by another, returning the quotient and remainder using long division.
    // WARNING: This is a simple binary long division. More efficient algorithms should be considered.
    fn div(self: Self, other: Self) -> (Self, Self) {
        assert(!other.is_zero());

        if self.lt(other) {
            (LargeInteger::zero(), self)
        } else {
            let mut rem = self;
            let mut quo = LargeInteger::zero();

            let bit_diff = self.nbits() - other.nbits();
            let mut c = other.shl(bit_diff);

            for i in 0..MAX_BITS+1 {
                if i as u64 <= bit_diff {
                    if rem.gte(c) {
                        rem = rem.sub(c);
                        quo = quo.shl1().add(LargeInteger::one());
                    } else {
                        quo = quo.shl1();
                    }
                    c = c.shr1();
                }
            };

            (quo, rem)
        }
    }

    /// Checks if the two LargeInteger instances are equal.
    fn eq(self: Self, other: Self) -> bool {
        let mut is_eq = true;
        for i in 0..NUM_LIMBS {
            is_eq = is_eq & (self.limbs[i] == other.limbs[i]);
        }
        is_eq
    }

    /// Checks if the LargeInteger instance is greater than or equal to another.
    fn gte(self: Self, other: Self) -> bool {
        let (_diff, borrow) = self.sbb(other);
        borrow == 0
    }

    /// Checks if the LargeInteger instance is strictly greater than another.
    fn gt(self: Self, other: Self) -> bool {
        let (diff, borrow) = self.sbb(other);
        (borrow == 0) & !diff.eq(LargeInteger::zero())
    }

    /// Checks if the LargeInteger instance is less than or equal to another.
    fn lte(self: Self, other: Self) -> bool {
        other.gte(self)
    }

    /// Checks if the LargeInteger instance is strictly less than another.
    fn lt(self: Self, other: Self) -> bool {
        other.gt(self)
    }

    /// Checks if the LargeInteger instance is zero.
    fn is_zero(self: Self) -> bool {
        self.eq(LargeInteger::zero())
    }

    /// Returns self + other % modulus.
    /// Assumes `self + other` as unbounded integer is `< 2*modulus`.
    fn addmod(self: Self, other: Self, modulus: Self) -> Self {
        let (sum1, carry) = self.adc(other);

        // Attempt to subtract the modulus, to ensure the result is in the field.
        let (sum2, borrow1) = sum1.sbb(modulus);
        let (_diff, borrow2) = utils::sbb(carry, 0, borrow1);

        if borrow2 == 0 {
            sum2
        } else {
            sum2.add(modulus)
        }
    }
    
    // Returns self * other % modulus.
    fn mulmod(self: Self, other: Self, modulus: Self) -> Self {
        // We assume that the mul is < 2^MAX_BITS, so we can just mod the low part.
        let (lo, _hi) = self.mul(other);
        assert(_hi.is_zero());

        let (quo, rem) = lo.div_unsafe(modulus);
        let (quo_modulus, _hi) = quo.mul(modulus);
        let reconstructed_lo = quo_modulus.add(rem);

        // Range check to prevent malicious prover from assigning random values for quo and rem
        assert(rem.lt(modulus));
        assert(quo.lte(lo));

        // Constrain that quo * mod + rem == original
        assert(reconstructed_lo.eq(lo));

        rem
    }

    unconstrained fn div_unsafe(self: Self, other: Self) -> (Self, Self) {
        self.div(other)
    }

    // Returns self * self % modulus.
    fn squaremod(self: Self, modulus: Self) -> Self {
        let rem = self.mulmod(self, modulus);
        
        rem
    }

    // Returns self ^ e % modulus.
    fn powmod(self: Self, e: Self, modulus: Self) -> Self {
        // Check e is less than 2^17, since function will only iterate through first 17 bits
        // Enable the most common exponents e.g. 65537
        assert(e.lt(LargeInteger::from_integer(131072 as u64)));
        let e_bits = e.to_bits();

        let mut res = LargeInteger::one();
        let mut pow = self;

        // TODO: Enable e up to MAX_BITS for generalization
        for i in 0..17 {
            if e_bits[i] as u1 == 1 {
                res = res.mulmod(pow, modulus);
            }
            pow = pow.squaremod(modulus);
            //println(e_bits[i]);
        }

        res
    }

    // Prints the LargeInteger instance as a byte array.
    fn println(self: Self) {
        let bytes = self.to_bytes();
        println(bytes);
    }
}

impl Add for LargeInteger {
    fn add(self: Self, other: Self) -> Self {
        self.add(other)
    }
}

impl Sub for LargeInteger {
    fn sub(self: Self, other: Self) -> Self {
        self.sub(other)
    }
}

impl Mul for LargeInteger {
    fn mul(self, other: Self) -> Self {
        let (lo, _hi) = self.mul(other);
        lo
    }
}

impl Div for LargeInteger {
    fn div(self, other: Self) -> Self {
        let (lo, _hi) = self.div(other);
        lo
    }
}

impl Rem for LargeInteger {
    fn rem(self, modulus: Self) -> Self {
        let (quo, rem) = self.div_unsafe(modulus);
        let (quo_modulus, _hi) = quo.mul(modulus);
        let reconstructed_lo = quo_modulus.add(rem);

        // Range check to prevent malicious prover from assigning random values for quo and rem
        assert(rem.lt(modulus));
        assert(quo.lte(self));

        // Constrain that quo * mod + rem == original
        assert(reconstructed_lo.eq(self));

        rem
    }
}

// impl Shl for LargeInteger {
//     fn shl(self, other: Self) -> Self {
//         self.shl(other.to_integer())
//     }
// }

// impl Shr for LargeInteger {
//     fn shr(self, other: Self) -> Self {
//         self.shr(other.to_integer())
//     }
// }

impl Eq for LargeInteger {
    fn eq(self: Self, other: Self) -> bool {
        self.eq(other)
    }
}

impl Ord for LargeInteger {
    fn cmp(self: Self, other: Self) -> Ordering {
        if self.lt(other) {
            Ordering::less()
        } else if self.gt(other) {
            Ordering::greater()
        } else {
            Ordering::equal()
        }
    }
}


#[test]
fn test_to_bytes1() {
    let a = LargeInteger::zero();
    let b = LargeInteger::one();

    let (c, _) = a.sbb(b);
    assert(c.to_bytes() == [255 as u8; MAX_BYTES]);
}

#[test]
fn test_to_bits1() {
    let a = LargeInteger::zero();
    let b = LargeInteger::one();

    let (c, _) = a.sbb(b);
    assert(c.to_bits() == [1 as u1; MAX_BITS]);
}

#[test]
fn test_add1() {
    let a = LargeInteger::from_bytes([1]);
    let b = LargeInteger::from_bytes([2]);
    let sum = a.add(b);

    assert(sum == LargeInteger::from_bytes([3]));
}

#[test]
fn test_sub1() {
    let a = LargeInteger::from_bytes([5]);
    let b = LargeInteger::from_bytes([3]);
    let diff = a.sub(b);

    assert(diff == LargeInteger::from_bytes([2]));
}

#[test]
fn test_mul1() {
    let a = LargeInteger::from_bytes([2]);
    let b = LargeInteger::from_bytes([3]);
    let (lo, hi) = a.mul(b);

    assert(lo == LargeInteger::from_bytes([6]));
    assert(hi.is_zero());
}

#[test]
fn test_mul2() {
    let max = LargeInteger { limbs: [0xffffffffffffffff; NUM_LIMBS] };
    let b = LargeInteger::from_bytes([3]);
    let (lo, hi) = max.mul(b);
    // 0xffffffffffffffff * 3 = 0x2fffffffffffffffd
    // So one 2 in the high part and 0xfffffffffffffffd in the low part
    assert(hi == LargeInteger::from_bytes([2]));
    assert(lo.limbs[0] == 0xfffffffffffffffd);
}

#[test]
fn test_cmp1() {
    let a = LargeInteger::from_bytes([2, 0]);
    let b = LargeInteger::from_bytes([0, 2]);

    assert(a != b);

    assert(a.lte(b));
    assert(!a.gte(b));

    assert(a.lt(b));
    assert(!a.gt(b));
}

#[test]
fn test_cmp2() {
    let a = LargeInteger::from_bytes([0, 2]);
    let b = LargeInteger::from_bytes([0, 2]);

    assert(a == b);

    assert(a <= b);
    assert(a >= b);

    assert(!(a < b));
    assert(!(a > b));
}

#[test]
fn test_shl1() {
    let a = LargeInteger::from_bytes([1, 2]);
    let b = a.shl(0);

    assert(a == b);
}

#[test]
fn test_shl2() {
    let a = LargeInteger::from_bytes([1, 2]);
    let b = a.shl(MAX_BITS as u64);

    assert(b.is_zero());
}

#[test]
fn test_shl3() {
    let a = LargeInteger::from_bytes([1, 2]);
    let b = a.shl(1);

    let bytes = b.to_bytes();

    let mut expected = [0 as u8; MAX_BYTES];
    expected[0] = 2;
    expected[1] = 4;

    assert(bytes == expected);
}

#[test]
fn test_shl4() {
    let a = LargeInteger::from_bytes([1, 2]);
    let b = a.shl(8);

    assert(b == LargeInteger::from_bytes([0, 1, 2]));
}

#[test]
fn test_shl5() {
    let a = LargeInteger::from_bytes([1]);
    let b = a.shl1();

    assert(b == LargeInteger::from_bytes([2]));
}

#[test]
fn test_shr1() {
    let a = LargeInteger::from_bytes([1, 2]);
    let b = a.shr(0);

    assert(a == b);
}

#[test]
fn test_shr2() {
    let a = LargeInteger::from_bytes([1, 2]);
    let b = a.shr(MAX_BITS as u64);

    assert(b.is_zero());
}

#[test]
fn test_shr3() {
    let a = LargeInteger::from_bytes([2, 4]);
    let b = a.shr1();

    let bytes = b.to_bytes();

    let mut expected = [0 as u8; MAX_BYTES];
    expected[0] = 1;
    expected[1] = 2;

    assert(bytes == expected);
}

#[test]
fn test_shr4() {
    let a = LargeInteger::from_bytes([0, 1, 2]);
    let b = a.shr(8);

    assert(b == LargeInteger::from_bytes([1, 2]));
}

#[test]
fn test_bits1() {
    let a = LargeInteger::from_bytes([0]);
    let b = a.nbits();

    assert(b == 0);
}

#[test]
fn test_bits2() {
    let a = LargeInteger::from_bytes([1]);
    let b = a.nbits();

    assert(b == 1);
}

#[test]
fn test_bits3() {
    let a = LargeInteger::from_bytes([255 as u8]);
    let b = a.nbits();

    assert(b == 8);
}

#[test]
fn test_bits4() {
    let a = LargeInteger::from_bytes([1, 5]);
    let b = a.nbits();

    assert(b == 11);
}

#[test]
fn test_addmod1() {
    let a = LargeInteger::from_bytes([2]);
    let b = LargeInteger::from_bytes([7]);
    let c = LargeInteger::from_bytes([5]);

    let d = a.addmod(b, c);
    assert(d == LargeInteger::from_bytes([4]));
}

#[test]
fn test_sbb1() {
    let a = LargeInteger::from_integer(1);
    let b = LargeInteger::from_integer(1);
    let (diff, borrow) = a.sbb(b);

    assert(diff.is_zero());
    assert(borrow == 0);
}

#[test]
fn test_sbb2() {
    let a = LargeInteger::from_integer(1);
    let b = LargeInteger::from_integer(2);
    let (diff, borrow) = a.sbb(b);

    assert(diff == LargeInteger { limbs: [0xffffffffffffffff; NUM_LIMBS] });
    assert(borrow >> (BITS_PER_LIMB - 1) as u8 == 1);
}


#[test]
fn test_div() {
    let a = LargeInteger::from_integer(123);
    let b = LargeInteger::from_integer(3);
    let (quo, rem) = a.div_unsafe(b);
    assert(quo == LargeInteger::from_integer(41));
    assert(rem == LargeInteger::from_integer(0));
}

#[test]
fn test_mac() {
    let max = 0xffffffffffffffff;
    let a = max;
    let b = 3;
    let (res, carry) = utils::mac(0, a, b, 0);
    // 0xffffffffffffffff * 3 = 0x2fffffffffffffffd
    // So one 2 in the carry and 0xfffffffffffffffd as a result
    assert(res == 0xfffffffffffffffd);
    assert(carry == 2);
}

#[test]
fn test_large_u128_div() {
    let mut a = U128::from_hex("0xffffffffffffffffffffffffffffffff");
    let mut b = U128::from_integer(5);
    let mut quo = a.div_without_overflow(b);
    assert(quo == U128::from_hex("0x33333333333333333333333333333333"));

    a = U128::from_hex("0x7fffffffffffffffffffffffffffffff");
    b = U128::from_integer(3);
    quo = a.div_without_overflow(b);
    assert(quo == U128::from_hex("0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
}