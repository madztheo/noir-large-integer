use crate::BITS_PER_LIMB as BITS;
use dep::u128_extension::U128Extension;
use dep::std::wrapping_sub;

// NOTE: this file is forked from https://github.com/SetProtocol/noir-rsa
// NOTE: this file is forked from https://github.com/shuklaayush/noir-bigint v0.1.0

// Compute a + b + carry, returning the result and the new carry over.
pub fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let ret = a as Field + b as Field + carry as Field;
    (ret as u64, (U128::from_integer(ret).large_shr(U128::from_integer(BITS))).to_integer())
}

// Compute a - (b + borrow), returning the result and the new borrow.
pub fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let ret = U128::from_integer(a).wrapping_sub(U128::from_integer(b) + (U128::from_integer(borrow) >> (BITS - 1) as u8));
    (ret.to_integer(), (ret.large_shr(U128::from_integer(BITS))).to_integer())
}

// Compute a + (b * c) + carry, returning the result and the new carry over.
pub fn mac(a: u64, b: u64, c: u64, carry: u64) -> (u64, u64) {
    let ret = (a as Field) + ((b as Field) * (c as Field)) + (carry as Field);
    (ret as u64, (U128::from_integer(ret).large_shr(U128::from_integer(BITS))).to_integer())
}
