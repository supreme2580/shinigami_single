use core::dict::{Felt252Dict, Felt252DictEntryTrait};

// ripemd160.cairo

pub(crate) const POW_2_32: u64 = 0x100000000;
pub(crate) const POW_2_8: u32 = 256;

pub(crate) fn get_pow_2(n: u32) -> u32 {
    match n {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        4 => 16,
        5 => 32,
        6 => 64,
        7 => 128,
        8 => 256,
        9 => 512,
        10 => 1024,
        11 => 2048,
        12 => 4096,
        13 => 8192,
        14 => 16384,
        15 => 32768,
        16 => 65536,
        17 => 131072,
        18 => 262144,
        19 => 524288,
        20 => 1048576,
        21 => 2097152,
        22 => 4194304,
        23 => 8388608,
        24 => 16777216,
        25 => 33554432,
        26 => 67108864,
        27 => 134217728,
        28 => 268435456,
        29 => 536870912,
        30 => 1073741824,
        31 => 2147483648,
        _ => 0
    }
}

pub(crate) fn u32_mod_add(a: u32, b: u32) -> u32 {
    let a: u64 = a.into();
    let b: u64 = b.into();
    ((a + b) % POW_2_32).try_into().unwrap()
}

pub(crate) fn u32_mod_add_3(a: u32, b: u32, c: u32) -> u32 {
    let result: u64 = (a.into() + b.into() + c.into()) % POW_2_32;
    result.try_into().unwrap()
}

pub(crate) fn u32_mod_add_4(a: u32, b: u32, c: u32, d: u32) -> u32 {
    let result: u64 = (a.into() + b.into() + c.into() + d.into()) % POW_2_32;
    result.try_into().unwrap()
}

pub(crate) fn u32_mod_mul(a: u32, b: u32) -> u32 {
    let a: u64 = a.into();
    let b: u64 = b.into();
    ((a * b) % POW_2_32).try_into().unwrap()
}

pub(crate) fn u32_leftrotate(x: u32, n: u32) -> u32 {
    let overflow = x / get_pow_2(32 - n);
    let shifted = u32_mod_mul(x, get_pow_2(n));
    shifted | overflow
}

pub(crate) fn u32_byte_swap(mut x: u32) -> u32 {
    let mask: u32 = 0x000000FF;
    let mut result = x & mask;
    result *= POW_2_8;
    x = x / POW_2_8;
    result += x & mask;
    result *= POW_2_8;
    x = x / POW_2_8;
    result += x & mask;
    result *= POW_2_8;
    x = x / POW_2_8;
    result += x & mask;
    result
}

pub(crate) fn bytes_to_u32_swap(bytes: @ByteArray, mut index: usize) -> u32 {
    let mut result: u32 = 0;
    result += bytes.at(index + 3).unwrap().into();
    result *= POW_2_8;
    result += bytes.at(index + 2).unwrap().into();
    result *= POW_2_8;
    result += bytes.at(index + 1).unwrap().into();
    result *= POW_2_8;
    result += bytes.at(index).unwrap().into();
    result
}

const BLOCK_SIZE: u32 = 64;
const BLOCK_SIZE_WO_LEN: u32 = 56;

#[derive(Drop, Clone, Copy)]
pub struct RIPEMD160Context {
    h0: u32,
    h1: u32,
    h2: u32,
    h3: u32,
    h4: u32,
}

pub impl RIPEMD160ContextIntoU256 of Into<RIPEMD160Context, u256> {
    fn into(self: RIPEMD160Context) -> u256 {
        ripemd160_context_as_u256(@self)
    }
}

pub impl RIPEMD160ContextIntoBytes of Into<RIPEMD160Context, ByteArray> {
    fn into(self: RIPEMD160Context) -> ByteArray {
        ripemd160_context_as_bytes(@self)
    }
}

pub impl RIPEMD160ContextIntoArray of Into<RIPEMD160Context, Array<u32>> {
    fn into(self: RIPEMD160Context) -> Array<u32> {
        ripemd160_context_as_array(@self)
    }
}

fn f(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

fn g(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (~x & z)
}

fn h(x: u32, y: u32, z: u32) -> u32 {
    (x | ~y) ^ z
}

fn i(x: u32, y: u32, z: u32) -> u32 {
    (x & z) | (y & ~z)
}

fn j(x: u32, y: u32, z: u32) -> u32 {
    x ^ (y | ~z)
}

fn l1(ref a: u32, b: u32, ref c: u32, d: u32, e: u32, x: u32, s: u32) {
    a = u32_mod_add_3(a, f(b, c, d), x);
    a = u32_mod_add(u32_leftrotate(a, s), e);
    c = u32_leftrotate(c, 10);
}

fn l2(ref a: u32, b: u32, ref c: u32, d: u32, e: u32, x: u32, s: u32) {
    a = u32_mod_add_4(a, g(b, c, d), x, 0x5a827999);
    a = u32_mod_add(u32_leftrotate(a, s), e);
    c = u32_leftrotate(c, 10);
}

fn l3(ref a: u32, b: u32, ref c: u32, d: u32, e: u32, x: u32, s: u32) {
    a = u32_mod_add_4(a, h(b, c, d), x, 0x6ed9eba1);
    a = u32_mod_add(u32_leftrotate(a, s), e);
    c = u32_leftrotate(c, 10);
}

fn l4(ref a: u32, b: u32, ref c: u32, d: u32, e: u32, x: u32, s: u32) {
    a = u32_mod_add_4(a, i(b, c, d), x, 0x8f1bbcdc);
    a = u32_mod_add(u32_leftrotate(a, s), e);
    c = u32_leftrotate(c, 10);
}

fn l5(ref a: u32, b: u32, ref c: u32, d: u32, e: u32, x: u32, s: u32) {
    a = u32_mod_add_4(a, j(b, c, d), x, 0xa953fd4e);
    a = u32_mod_add(u32_leftrotate(a, s), e);
    c = u32_leftrotate(c, 10);
}

fn r1(ref a: u32, b: u32, ref c: u32, d: u32, e: u32, x: u32, s: u32) {
    a = u32_mod_add_4(a, j(b, c, d), x, 0x50a28be6);
    a = u32_mod_add(u32_leftrotate(a, s), e);
    c = u32_leftrotate(c, 10);
}

fn r2(ref a: u32, b: u32, ref c: u32, d: u32, e: u32, x: u32, s: u32) {
    a = u32_mod_add_4(a, i(b, c, d), x, 0x5c4dd124);
    a = u32_mod_add(u32_leftrotate(a, s), e);
    c = u32_leftrotate(c, 10);
}

fn r3(ref a: u32, b: u32, ref c: u32, d: u32, e: u32, x: u32, s: u32) {
    a = u32_mod_add_4(a, h(b, c, d), x, 0x6d703ef3);
    a = u32_mod_add(u32_leftrotate(a, s), e);
    c = u32_leftrotate(c, 10);
}

fn r4(ref a: u32, b: u32, ref c: u32, d: u32, e: u32, x: u32, s: u32) {
    a = u32_mod_add_4(a, g(b, c, d), x, 0x7a6d76e9);
    a = u32_mod_add(u32_leftrotate(a, s), e);
    c = u32_leftrotate(c, 10);
}

fn r5(ref a: u32, b: u32, ref c: u32, d: u32, e: u32, x: u32, s: u32) {
    a = u32_mod_add_3(a, f(b, c, d), x);
    a = u32_mod_add(u32_leftrotate(a, s), e);
    c = u32_leftrotate(c, 10);
}

// RIPEMD-160 compression function
fn ripemd160_process_block(ref ctx: RIPEMD160Context, block: @Array<u32>) {
    let mut lh0 = ctx.h0;
    let mut lh1 = ctx.h1;
    let mut lh2 = ctx.h2;
    let mut lh3 = ctx.h3;
    let mut lh4 = ctx.h4;
    let mut rh0 = ctx.h0;
    let mut rh1 = ctx.h1;
    let mut rh2 = ctx.h2;
    let mut rh3 = ctx.h3;
    let mut rh4 = ctx.h4;

    // Left round 1
    l1(ref lh0, lh1, ref lh2, lh3, lh4, *block.at(0), 11);
    l1(ref lh4, lh0, ref lh1, lh2, lh3, *block.at(1), 14);
    l1(ref lh3, lh4, ref lh0, lh1, lh2, *block.at(2), 15);
    l1(ref lh2, lh3, ref lh4, lh0, lh1, *block.at(3), 12);
    l1(ref lh1, lh2, ref lh3, lh4, lh0, *block.at(4), 5);
    l1(ref lh0, lh1, ref lh2, lh3, lh4, *block.at(5), 8);
    l1(ref lh4, lh0, ref lh1, lh2, lh3, *block.at(6), 7);
    l1(ref lh3, lh4, ref lh0, lh1, lh2, *block.at(7), 9);
    l1(ref lh2, lh3, ref lh4, lh0, lh1, *block.at(8), 11);
    l1(ref lh1, lh2, ref lh3, lh4, lh0, *block.at(9), 13);
    l1(ref lh0, lh1, ref lh2, lh3, lh4, *block.at(10), 14);
    l1(ref lh4, lh0, ref lh1, lh2, lh3, *block.at(11), 15);
    l1(ref lh3, lh4, ref lh0, lh1, lh2, *block.at(12), 6);
    l1(ref lh2, lh3, ref lh4, lh0, lh1, *block.at(13), 7);
    l1(ref lh1, lh2, ref lh3, lh4, lh0, *block.at(14), 9);
    l1(ref lh0, lh1, ref lh2, lh3, lh4, *block.at(15), 8);

    // Left round 2
    l2(ref lh4, lh0, ref lh1, lh2, lh3, *block.at(7), 7);
    l2(ref lh3, lh4, ref lh0, lh1, lh2, *block.at(4), 6);
    l2(ref lh2, lh3, ref lh4, lh0, lh1, *block.at(13), 8);
    l2(ref lh1, lh2, ref lh3, lh4, lh0, *block.at(1), 13);
    l2(ref lh0, lh1, ref lh2, lh3, lh4, *block.at(10), 11);
    l2(ref lh4, lh0, ref lh1, lh2, lh3, *block.at(6), 9);
    l2(ref lh3, lh4, ref lh0, lh1, lh2, *block.at(15), 7);
    l2(ref lh2, lh3, ref lh4, lh0, lh1, *block.at(3), 15);
    l2(ref lh1, lh2, ref lh3, lh4, lh0, *block.at(12), 7);
    l2(ref lh0, lh1, ref lh2, lh3, lh4, *block.at(0), 12);
    l2(ref lh4, lh0, ref lh1, lh2, lh3, *block.at(9), 15);
    l2(ref lh3, lh4, ref lh0, lh1, lh2, *block.at(5), 9);
    l2(ref lh2, lh3, ref lh4, lh0, lh1, *block.at(2), 11);
    l2(ref lh1, lh2, ref lh3, lh4, lh0, *block.at(14), 7);
    l2(ref lh0, lh1, ref lh2, lh3, lh4, *block.at(11), 13);
    l2(ref lh4, lh0, ref lh1, lh2, lh3, *block.at(8), 12);

    // Left round 3
    l3(ref lh3, lh4, ref lh0, lh1, lh2, *block.at(3), 11);
    l3(ref lh2, lh3, ref lh4, lh0, lh1, *block.at(10), 13);
    l3(ref lh1, lh2, ref lh3, lh4, lh0, *block.at(14), 6);
    l3(ref lh0, lh1, ref lh2, lh3, lh4, *block.at(4), 7);
    l3(ref lh4, lh0, ref lh1, lh2, lh3, *block.at(9), 14);
    l3(ref lh3, lh4, ref lh0, lh1, lh2, *block.at(15), 9);
    l3(ref lh2, lh3, ref lh4, lh0, lh1, *block.at(8), 13);
    l3(ref lh1, lh2, ref lh3, lh4, lh0, *block.at(1), 15);
    l3(ref lh0, lh1, ref lh2, lh3, lh4, *block.at(2), 14);
    l3(ref lh4, lh0, ref lh1, lh2, lh3, *block.at(7), 8);
    l3(ref lh3, lh4, ref lh0, lh1, lh2, *block.at(0), 13);
    l3(ref lh2, lh3, ref lh4, lh0, lh1, *block.at(6), 6);
    l3(ref lh1, lh2, ref lh3, lh4, lh0, *block.at(13), 5);
    l3(ref lh0, lh1, ref lh2, lh3, lh4, *block.at(11), 12);
    l3(ref lh4, lh0, ref lh1, lh2, lh3, *block.at(5), 7);
    l3(ref lh3, lh4, ref lh0, lh1, lh2, *block.at(12), 5);

    // Left round 4
    l4(ref lh2, lh3, ref lh4, lh0, lh1, *block.at(1), 11);
    l4(ref lh1, lh2, ref lh3, lh4, lh0, *block.at(9), 12);
    l4(ref lh0, lh1, ref lh2, lh3, lh4, *block.at(11), 14);
    l4(ref lh4, lh0, ref lh1, lh2, lh3, *block.at(10), 15);
    l4(ref lh3, lh4, ref lh0, lh1, lh2, *block.at(0), 14);
    l4(ref lh2, lh3, ref lh4, lh0, lh1, *block.at(8), 15);
    l4(ref lh1, lh2, ref lh3, lh4, lh0, *block.at(12), 9);
    l4(ref lh0, lh1, ref lh2, lh3, lh4, *block.at(4), 8);
    l4(ref lh4, lh0, ref lh1, lh2, lh3, *block.at(13), 9);
    l4(ref lh3, lh4, ref lh0, lh1, lh2, *block.at(3), 14);
    l4(ref lh2, lh3, ref lh4, lh0, lh1, *block.at(7), 5);
    l4(ref lh1, lh2, ref lh3, lh4, lh0, *block.at(15), 6);
    l4(ref lh0, lh1, ref lh2, lh3, lh4, *block.at(14), 8);
    l4(ref lh4, lh0, ref lh1, lh2, lh3, *block.at(5), 6);
    l4(ref lh3, lh4, ref lh0, lh1, lh2, *block.at(6), 5);
    l4(ref lh2, lh3, ref lh4, lh0, lh1, *block.at(2), 12);

    // Left round 5
    l5(ref lh1, lh2, ref lh3, lh4, lh0, *block.at(4), 9);
    l5(ref lh0, lh1, ref lh2, lh3, lh4, *block.at(0), 15);
    l5(ref lh4, lh0, ref lh1, lh2, lh3, *block.at(5), 5);
    l5(ref lh3, lh4, ref lh0, lh1, lh2, *block.at(9), 11);
    l5(ref lh2, lh3, ref lh4, lh0, lh1, *block.at(7), 6);
    l5(ref lh1, lh2, ref lh3, lh4, lh0, *block.at(12), 8);
    l5(ref lh0, lh1, ref lh2, lh3, lh4, *block.at(2), 13);
    l5(ref lh4, lh0, ref lh1, lh2, lh3, *block.at(10), 12);
    l5(ref lh3, lh4, ref lh0, lh1, lh2, *block.at(14), 5);
    l5(ref lh2, lh3, ref lh4, lh0, lh1, *block.at(1), 12);
    l5(ref lh1, lh2, ref lh3, lh4, lh0, *block.at(3), 13);
    l5(ref lh0, lh1, ref lh2, lh3, lh4, *block.at(8), 14);
    l5(ref lh4, lh0, ref lh1, lh2, lh3, *block.at(11), 11);
    l5(ref lh3, lh4, ref lh0, lh1, lh2, *block.at(6), 8);
    l5(ref lh2, lh3, ref lh4, lh0, lh1, *block.at(15), 5);
    l5(ref lh1, lh2, ref lh3, lh4, lh0, *block.at(13), 6);

    core::internal::revoke_ap_tracking();

    // Right round 1
    r1(ref rh0, rh1, ref rh2, rh3, rh4, *block.at(5), 8);
    r1(ref rh4, rh0, ref rh1, rh2, rh3, *block.at(14), 9);
    r1(ref rh3, rh4, ref rh0, rh1, rh2, *block.at(7), 9);
    r1(ref rh2, rh3, ref rh4, rh0, rh1, *block.at(0), 11);
    r1(ref rh1, rh2, ref rh3, rh4, rh0, *block.at(9), 13);
    r1(ref rh0, rh1, ref rh2, rh3, rh4, *block.at(2), 15);
    r1(ref rh4, rh0, ref rh1, rh2, rh3, *block.at(11), 15);
    r1(ref rh3, rh4, ref rh0, rh1, rh2, *block.at(4), 5);
    r1(ref rh2, rh3, ref rh4, rh0, rh1, *block.at(13), 7);
    r1(ref rh1, rh2, ref rh3, rh4, rh0, *block.at(6), 7);
    r1(ref rh0, rh1, ref rh2, rh3, rh4, *block.at(15), 8);
    r1(ref rh4, rh0, ref rh1, rh2, rh3, *block.at(8), 11);
    r1(ref rh3, rh4, ref rh0, rh1, rh2, *block.at(1), 14);
    r1(ref rh2, rh3, ref rh4, rh0, rh1, *block.at(10), 14);
    r1(ref rh1, rh2, ref rh3, rh4, rh0, *block.at(3), 12);
    r1(ref rh0, rh1, ref rh2, rh3, rh4, *block.at(12), 6);

    // Right round 2
    r2(ref rh4, rh0, ref rh1, rh2, rh3, *block.at(6), 9);
    r2(ref rh3, rh4, ref rh0, rh1, rh2, *block.at(11), 13);
    r2(ref rh2, rh3, ref rh4, rh0, rh1, *block.at(3), 15);
    r2(ref rh1, rh2, ref rh3, rh4, rh0, *block.at(7), 7);
    r2(ref rh0, rh1, ref rh2, rh3, rh4, *block.at(0), 12);
    r2(ref rh4, rh0, ref rh1, rh2, rh3, *block.at(13), 8);
    r2(ref rh3, rh4, ref rh0, rh1, rh2, *block.at(5), 9);
    r2(ref rh2, rh3, ref rh4, rh0, rh1, *block.at(10), 11);
    r2(ref rh1, rh2, ref rh3, rh4, rh0, *block.at(14), 7);
    r2(ref rh0, rh1, ref rh2, rh3, rh4, *block.at(15), 7);
    r2(ref rh4, rh0, ref rh1, rh2, rh3, *block.at(8), 12);
    r2(ref rh3, rh4, ref rh0, rh1, rh2, *block.at(12), 7);
    r2(ref rh2, rh3, ref rh4, rh0, rh1, *block.at(4), 6);
    r2(ref rh1, rh2, ref rh3, rh4, rh0, *block.at(9), 15);
    r2(ref rh0, rh1, ref rh2, rh3, rh4, *block.at(1), 13);
    r2(ref rh4, rh0, ref rh1, rh2, rh3, *block.at(2), 11);

    // Right round 3
    r3(ref rh3, rh4, ref rh0, rh1, rh2, *block.at(15), 9);
    r3(ref rh2, rh3, ref rh4, rh0, rh1, *block.at(5), 7);
    r3(ref rh1, rh2, ref rh3, rh4, rh0, *block.at(1), 15);
    r3(ref rh0, rh1, ref rh2, rh3, rh4, *block.at(3), 11);
    r3(ref rh4, rh0, ref rh1, rh2, rh3, *block.at(7), 8);
    r3(ref rh3, rh4, ref rh0, rh1, rh2, *block.at(14), 6);
    r3(ref rh2, rh3, ref rh4, rh0, rh1, *block.at(6), 6);
    r3(ref rh1, rh2, ref rh3, rh4, rh0, *block.at(9), 14);
    r3(ref rh0, rh1, ref rh2, rh3, rh4, *block.at(11), 12);
    r3(ref rh4, rh0, ref rh1, rh2, rh3, *block.at(8), 13);
    r3(ref rh3, rh4, ref rh0, rh1, rh2, *block.at(12), 5);
    r3(ref rh2, rh3, ref rh4, rh0, rh1, *block.at(2), 14);
    r3(ref rh1, rh2, ref rh3, rh4, rh0, *block.at(10), 13);
    r3(ref rh0, rh1, ref rh2, rh3, rh4, *block.at(0), 13);
    r3(ref rh4, rh0, ref rh1, rh2, rh3, *block.at(4), 7);
    r3(ref rh3, rh4, ref rh0, rh1, rh2, *block.at(13), 5);

    // Right round 4
    r4(ref rh2, rh3, ref rh4, rh0, rh1, *block.at(8), 15);
    r4(ref rh1, rh2, ref rh3, rh4, rh0, *block.at(6), 5);
    r4(ref rh0, rh1, ref rh2, rh3, rh4, *block.at(4), 8);
    r4(ref rh4, rh0, ref rh1, rh2, rh3, *block.at(1), 11);
    r4(ref rh3, rh4, ref rh0, rh1, rh2, *block.at(3), 14);
    r4(ref rh2, rh3, ref rh4, rh0, rh1, *block.at(11), 14);
    r4(ref rh1, rh2, ref rh3, rh4, rh0, *block.at(15), 6);
    r4(ref rh0, rh1, ref rh2, rh3, rh4, *block.at(0), 14);
    r4(ref rh4, rh0, ref rh1, rh2, rh3, *block.at(5), 6);
    r4(ref rh3, rh4, ref rh0, rh1, rh2, *block.at(12), 9);
    r4(ref rh2, rh3, ref rh4, rh0, rh1, *block.at(2), 12);
    r4(ref rh1, rh2, ref rh3, rh4, rh0, *block.at(13), 9);
    r4(ref rh0, rh1, ref rh2, rh3, rh4, *block.at(9), 12);
    r4(ref rh4, rh0, ref rh1, rh2, rh3, *block.at(7), 5);
    r4(ref rh3, rh4, ref rh0, rh1, rh2, *block.at(10), 15);
    r4(ref rh2, rh3, ref rh4, rh0, rh1, *block.at(14), 8);

    // Right round 5
    r5(ref rh1, rh2, ref rh3, rh4, rh0, *block.at(12), 8);
    r5(ref rh0, rh1, ref rh2, rh3, rh4, *block.at(15), 5);
    r5(ref rh4, rh0, ref rh1, rh2, rh3, *block.at(10), 12);
    r5(ref rh3, rh4, ref rh0, rh1, rh2, *block.at(4), 9);
    r5(ref rh2, rh3, ref rh4, rh0, rh1, *block.at(1), 12);
    r5(ref rh1, rh2, ref rh3, rh4, rh0, *block.at(5), 5);
    r5(ref rh0, rh1, ref rh2, rh3, rh4, *block.at(8), 14);
    r5(ref rh4, rh0, ref rh1, rh2, rh3, *block.at(7), 6);
    r5(ref rh3, rh4, ref rh0, rh1, rh2, *block.at(6), 8);
    r5(ref rh2, rh3, ref rh4, rh0, rh1, *block.at(2), 13);
    r5(ref rh1, rh2, ref rh3, rh4, rh0, *block.at(13), 6);
    r5(ref rh0, rh1, ref rh2, rh3, rh4, *block.at(14), 5);
    r5(ref rh4, rh0, ref rh1, rh2, rh3, *block.at(0), 15);
    r5(ref rh3, rh4, ref rh0, rh1, rh2, *block.at(3), 13);
    r5(ref rh2, rh3, ref rh4, rh0, rh1, *block.at(9), 11);
    r5(ref rh1, rh2, ref rh3, rh4, rh0, *block.at(11), 11);

    // Combine results
    rh3 = u32_mod_add_3(ctx.h1, lh2, rh3);
    ctx.h1 = u32_mod_add_3(ctx.h2, lh3, rh4);
    ctx.h2 = u32_mod_add_3(ctx.h3, lh4, rh0);
    ctx.h3 = u32_mod_add_3(ctx.h4, lh0, rh1);
    ctx.h4 = u32_mod_add_3(ctx.h0, lh1, rh2);
    ctx.h0 = rh3;
}

// Add RIPEMD-160 padding to the input.
fn ripemd160_padding(ref data: ByteArray) {
    // Get message len in bits
    let mut data_bits_len: felt252 = data.len().into() * 8;

    // Append padding bit
    data.append_byte(0x80);

    // Add padding zeroes
    let mut len = data.len();
    while (len % BLOCK_SIZE != BLOCK_SIZE_WO_LEN) {
        data.append_byte(0);
        len += 1;
    };

    // Add message len in little-endian
    data.append_word_rev(data_bits_len, 8);
}

// Update the context by processing the whole data.
fn ripemd160_update(ref ctx: RIPEMD160Context, data: ByteArray) {
    let mut i: usize = 0;
    let mut j: usize = 0;
    let len = data.len();
    while (i != len) {
        let mut block: Array<u32> = ArrayTrait::new();
        j = 0;
        while (j < BLOCK_SIZE) {
            block.append(bytes_to_u32_swap(@data, i));
            j += 4;
            i += 4;
        };
        ripemd160_process_block(ref ctx, @block);
    };
    ctx.h0 = u32_byte_swap(ctx.h0);
    ctx.h1 = u32_byte_swap(ctx.h1);
    ctx.h2 = u32_byte_swap(ctx.h2);
    ctx.h3 = u32_byte_swap(ctx.h3);
    ctx.h4 = u32_byte_swap(ctx.h4);
}

// Init context with RIPEMD-160 constant.
fn ripemd160_init() -> RIPEMD160Context {
    RIPEMD160Context {
        h0: 0x67452301, h1: 0xefcdab89, h2: 0x98badcfe, h3: 0x10325476, h4: 0xc3d2e1f0,
    }
}

// Return hash as bytes.
pub fn ripemd160_context_as_bytes(ctx: @RIPEMD160Context) -> ByteArray {
    let mut result: ByteArray = Default::default();
    result.append_word((*ctx.h0).into(), 4);
    result.append_word((*ctx.h1).into(), 4);
    result.append_word((*ctx.h2).into(), 4);
    result.append_word((*ctx.h3).into(), 4);
    result.append_word((*ctx.h4).into(), 4);
    result
}

// Return hash as u32 array.
pub fn ripemd160_context_as_array(ctx: @RIPEMD160Context) -> Array<u32> {
    let mut result: Array<u32> = ArrayTrait::new();
    result.append(*ctx.h0);
    result.append(*ctx.h1);
    result.append(*ctx.h2);
    result.append(*ctx.h3);
    result.append(*ctx.h4);
    result
}

// Return hash as u256.
pub fn ripemd160_context_as_u256(ctx: @RIPEMD160Context) -> u256 {
    let mut result: u256 = 0;
    result += (*ctx.h0).into();
    result *= POW_2_32.into();
    result += (*ctx.h1).into();
    result *= POW_2_32.into();
    result += (*ctx.h2).into();
    result *= POW_2_32.into();
    result += (*ctx.h3).into();
    result *= POW_2_32.into();
    result += (*ctx.h4).into();
    result
}

// RIPEMD-160 hash function entrypoint.
pub fn ripemd160_hash(data: @ByteArray) -> RIPEMD160Context {
    let mut data = data.clone();
    let mut ctx = ripemd160_init();
    ripemd160_padding(ref data);
    ripemd160_update(ref ctx, data);
    ctx
}

// sha1.cairo

pub(crate) fn u32_mod_add_5(a: u32, b: u32, c: u32, d: u32, e: u32) -> u32 {
    let result: u64 = (a.into() + b.into() + c.into() + d.into() + e.into()) % POW_2_32;
    result.try_into().unwrap()
}

pub(crate) fn bytes_to_u32(bytes: @ByteArray, mut index: usize) -> u32 {
    let mut result: u32 = 0;
    result += bytes.at(index).unwrap().into();
    result *= POW_2_8;
    result += bytes.at(index + 1).unwrap().into();
    result *= POW_2_8;
    result += bytes.at(index + 2).unwrap().into();
    result *= POW_2_8;
    result += bytes.at(index + 3).unwrap().into();
    result
}

#[derive(Drop, Clone, Copy)]
pub struct SHA1Context {
    h0: u32,
    h1: u32,
    h2: u32,
    h3: u32,
    h4: u32,
}

pub impl SHA1ContextIntoU256 of Into<SHA1Context, u256> {
    fn into(self: SHA1Context) -> u256 {
        sha1_context_as_u256(@self)
    }
}

pub impl SHA1ContextIntoBytes of Into<SHA1Context, ByteArray> {
    fn into(self: SHA1Context) -> ByteArray {
        sha1_context_as_bytes(@self)
    }
}

pub impl SHA1ContextIntoArray of Into<SHA1Context, Array<u32>> {
    fn into(self: SHA1Context) -> Array<u32> {
        sha1_context_as_array(@self)
    }
}

fn fs(x: u32, y: u32, z: u32) -> u32 {
    z ^ (x & (y ^ z))
}

fn gs(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

fn hs(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (z & (x | y))
}

fn w(x: u8, ref block: Felt252Dict<u32>) -> u32 {
    let a: felt252 = (x - 3 & 0x0F).into();
    let b: felt252 = (x - 8 & 0x0F).into();
    let c: felt252 = (x - 14 & 0x0F).into();
    let d: felt252 = (x & 0x0F).into();
    let temp = block[a] ^ block[b] ^ block[c] ^ block[d];
    block.insert(d, u32_leftrotate(temp, 1));
    block[d]
}

fn r0(h0: u32, ref h1: u32, h2: u32, h3: u32, ref h4: u32, x: u32) {
    h4 = u32_mod_add_5(h4, u32_leftrotate(h0, 5), fs(h1, h2, h3), 0x5A827999, x);
    h1 = u32_leftrotate(h1, 30);
}

fn r1s(h0: u32, ref h1: u32, h2: u32, h3: u32, ref h4: u32, x: u32) {
    h4 = u32_mod_add_5(h4, u32_leftrotate(h0, 5), gs(h1, h2, h3), 0x6ED9EBA1, x);
    h1 = u32_leftrotate(h1, 30);
}

fn r2s(h0: u32, ref h1: u32, h2: u32, h3: u32, ref h4: u32, x: u32) {
    h4 = u32_mod_add_5(h4, u32_leftrotate(h0, 5), hs(h1, h2, h3), 0x8F1BBCDC, x);
    h1 = u32_leftrotate(h1, 30);
}

fn r3s(h0: u32, ref h1: u32, h2: u32, h3: u32, ref h4: u32, x: u32) {
    h4 = u32_mod_add_5(h4, u32_leftrotate(h0, 5), gs(h1, h2, h3), 0xCA62C1D6, x);
    h1 = u32_leftrotate(h1, 30);
}

// SHA-1 compression function
fn sha1_process_block(ref ctx: SHA1Context, ref block: Felt252Dict<u32>) {
    let mut h0: u32 = ctx.h0;
    let mut h1: u32 = ctx.h1;
    let mut h2: u32 = ctx.h2;
    let mut h3: u32 = ctx.h3;
    let mut h4: u32 = ctx.h4;

    // Round 0
    r0(h0, ref h1, h2, h3, ref h4, block[0]);
    r0(h4, ref h0, h1, h2, ref h3, block[1]);
    r0(h3, ref h4, h0, h1, ref h2, block[2]);
    r0(h2, ref h3, h4, h0, ref h1, block[3]);
    r0(h1, ref h2, h3, h4, ref h0, block[4]);
    r0(h0, ref h1, h2, h3, ref h4, block[5]);
    r0(h4, ref h0, h1, h2, ref h3, block[6]);
    r0(h3, ref h4, h0, h1, ref h2, block[7]);
    r0(h2, ref h3, h4, h0, ref h1, block[8]);
    r0(h1, ref h2, h3, h4, ref h0, block[9]);
    r0(h0, ref h1, h2, h3, ref h4, block[10]);
    r0(h4, ref h0, h1, h2, ref h3, block[11]);
    r0(h3, ref h4, h0, h1, ref h2, block[12]);
    r0(h2, ref h3, h4, h0, ref h1, block[13]);
    r0(h1, ref h2, h3, h4, ref h0, block[14]);
    r0(h0, ref h1, h2, h3, ref h4, block[15]);
    r0(h4, ref h0, h1, h2, ref h3, w(16, ref block));
    r0(h3, ref h4, h0, h1, ref h2, w(17, ref block));
    r0(h2, ref h3, h4, h0, ref h1, w(18, ref block));
    r0(h1, ref h2, h3, h4, ref h0, w(19, ref block));

    // Round 1
    r1s(h0, ref h1, h2, h3, ref h4, w(20, ref block));
    r1s(h4, ref h0, h1, h2, ref h3, w(21, ref block));
    r1s(h3, ref h4, h0, h1, ref h2, w(22, ref block));
    r1s(h2, ref h3, h4, h0, ref h1, w(23, ref block));
    r1s(h1, ref h2, h3, h4, ref h0, w(24, ref block));
    r1s(h0, ref h1, h2, h3, ref h4, w(25, ref block));
    r1s(h4, ref h0, h1, h2, ref h3, w(26, ref block));
    r1s(h3, ref h4, h0, h1, ref h2, w(27, ref block));
    r1s(h2, ref h3, h4, h0, ref h1, w(28, ref block));
    r1s(h1, ref h2, h3, h4, ref h0, w(29, ref block));
    r1s(h0, ref h1, h2, h3, ref h4, w(30, ref block));
    r1s(h4, ref h0, h1, h2, ref h3, w(31, ref block));
    r1s(h3, ref h4, h0, h1, ref h2, w(32, ref block));
    r1s(h2, ref h3, h4, h0, ref h1, w(33, ref block));
    r1s(h1, ref h2, h3, h4, ref h0, w(34, ref block));
    r1s(h0, ref h1, h2, h3, ref h4, w(35, ref block));
    r1s(h4, ref h0, h1, h2, ref h3, w(36, ref block));
    r1s(h3, ref h4, h0, h1, ref h2, w(37, ref block));
    r1s(h2, ref h3, h4, h0, ref h1, w(38, ref block));
    r1s(h1, ref h2, h3, h4, ref h0, w(39, ref block));

    // Round 2
    r2s(h0, ref h1, h2, h3, ref h4, w(40, ref block));
    r2s(h4, ref h0, h1, h2, ref h3, w(41, ref block));
    r2s(h3, ref h4, h0, h1, ref h2, w(42, ref block));
    r2s(h2, ref h3, h4, h0, ref h1, w(43, ref block));
    r2s(h1, ref h2, h3, h4, ref h0, w(44, ref block));
    r2s(h0, ref h1, h2, h3, ref h4, w(45, ref block));
    r2s(h4, ref h0, h1, h2, ref h3, w(46, ref block));
    r2s(h3, ref h4, h0, h1, ref h2, w(47, ref block));
    r2s(h2, ref h3, h4, h0, ref h1, w(48, ref block));
    r2s(h1, ref h2, h3, h4, ref h0, w(49, ref block));
    r2s(h0, ref h1, h2, h3, ref h4, w(50, ref block));
    r2s(h4, ref h0, h1, h2, ref h3, w(51, ref block));
    r2s(h3, ref h4, h0, h1, ref h2, w(52, ref block));
    r2s(h2, ref h3, h4, h0, ref h1, w(53, ref block));
    r2s(h1, ref h2, h3, h4, ref h0, w(54, ref block));
    r2s(h0, ref h1, h2, h3, ref h4, w(55, ref block));
    r2s(h4, ref h0, h1, h2, ref h3, w(56, ref block));
    r2s(h3, ref h4, h0, h1, ref h2, w(57, ref block));
    r2s(h2, ref h3, h4, h0, ref h1, w(58, ref block));
    r2s(h1, ref h2, h3, h4, ref h0, w(59, ref block));

    // Round 3
    r3s(h0, ref h1, h2, h3, ref h4, w(60, ref block));
    r3s(h4, ref h0, h1, h2, ref h3, w(61, ref block));
    r3s(h3, ref h4, h0, h1, ref h2, w(62, ref block));
    r3s(h2, ref h3, h4, h0, ref h1, w(63, ref block));
    r3s(h1, ref h2, h3, h4, ref h0, w(64, ref block));
    r3s(h0, ref h1, h2, h3, ref h4, w(65, ref block));
    r3s(h4, ref h0, h1, h2, ref h3, w(66, ref block));
    r3s(h3, ref h4, h0, h1, ref h2, w(67, ref block));
    r3s(h2, ref h3, h4, h0, ref h1, w(68, ref block));
    r3s(h1, ref h2, h3, h4, ref h0, w(69, ref block));
    r3s(h0, ref h1, h2, h3, ref h4, w(70, ref block));
    r3s(h4, ref h0, h1, h2, ref h3, w(71, ref block));
    r3s(h3, ref h4, h0, h1, ref h2, w(72, ref block));
    r3s(h2, ref h3, h4, h0, ref h1, w(73, ref block));
    r3s(h1, ref h2, h3, h4, ref h0, w(74, ref block));
    r3s(h0, ref h1, h2, h3, ref h4, w(75, ref block));
    r3s(h4, ref h0, h1, h2, ref h3, w(76, ref block));
    r3s(h3, ref h4, h0, h1, ref h2, w(77, ref block));
    r3s(h2, ref h3, h4, h0, ref h1, w(78, ref block));
    r3s(h1, ref h2, h3, h4, ref h0, w(79, ref block));

    // Combine results
    ctx.h0 = u32_mod_add(ctx.h0, h0);
    ctx.h1 = u32_mod_add(ctx.h1, h1);
    ctx.h2 = u32_mod_add(ctx.h2, h2);
    ctx.h3 = u32_mod_add(ctx.h3, h3);
    ctx.h4 = u32_mod_add(ctx.h4, h4);
}

// Add SHA-1 padding to the input.
fn sha1_paddings(ref data: ByteArray) {
    // Get message len in bits
    let mut data_bits_len: felt252 = data.len().into() * 8;

    // Append padding bit
    data.append_byte(0x80);

    // Add padding zeroes
    let mut len = data.len();
    while (len % BLOCK_SIZE != BLOCK_SIZE_WO_LEN) {
        data.append_byte(0);
        len += 1;
    };

    // Add message len in big-endian
    data.append_word(data_bits_len, 8);
}

// Update the context by processing the whole data.
fn sha1_update(ref ctx: SHA1Context, data: ByteArray) {
    let mut i: usize = 0;
    let mut j: usize = 0;
    let len = data.len();
    let mut block: Felt252Dict<u32> = Default::default();
    while (i != len) {
        j = 0;
        let mut k: usize = 0;
        while (j < BLOCK_SIZE) {
            block.insert(k.into(), bytes_to_u32(@data, i));
            j += 4;
            i += 4;
            k += 1;
        };
        sha1_process_block(ref ctx, ref block);
    };
}

// Init context with SHA-1 constant.
fn sha1_init() -> SHA1Context {
    SHA1Context { h0: 0x67452301, h1: 0xefcdab89, h2: 0x98badcfe, h3: 0x10325476, h4: 0xc3d2e1f0, }
}

// Return hash as bytes.
pub fn sha1_context_as_bytes(ctx: @SHA1Context) -> ByteArray {
    let mut result: ByteArray = Default::default();
    result.append_word((*ctx.h0).into(), 4);
    result.append_word((*ctx.h1).into(), 4);
    result.append_word((*ctx.h2).into(), 4);
    result.append_word((*ctx.h3).into(), 4);
    result.append_word((*ctx.h4).into(), 4);
    result
}

// Return hash as u32 array.
pub fn sha1_context_as_array(ctx: @SHA1Context) -> Array<u32> {
    let mut result: Array<u32> = ArrayTrait::new();
    result.append(*ctx.h0);
    result.append(*ctx.h1);
    result.append(*ctx.h2);
    result.append(*ctx.h3);
    result.append(*ctx.h4);
    result
}

// Return hash as u256.
pub fn sha1_context_as_u256(ctx: @SHA1Context) -> u256 {
    let mut result: u256 = 0;
    result += (*ctx.h0).into();
    result *= POW_2_32.into();
    result += (*ctx.h1).into();
    result *= POW_2_32.into();
    result += (*ctx.h2).into();
    result *= POW_2_32.into();
    result += (*ctx.h3).into();
    result *= POW_2_32.into();
    result += (*ctx.h4).into();
    result
}

// SHA-1 hash function entrypoint.
pub fn sha1_hashs(data: @ByteArray) -> SHA1Context {
    let mut data = data.clone();
    let mut ctx = sha1_init();
    sha1_paddings(ref data);
    sha1_update(ref ctx, data);
    ctx
}

// error.cairo

pub mod Error {
    pub const SCRIPT_FAILED: felt252 = 'Script failed after execute';
    pub const SCRIPT_EMPTY_STACK: felt252 = 'Stack empty after execute';
    pub const SCRIPT_UNBALANCED_CONDITIONAL_STACK: felt252 = 'Unbalanced conditional';
    pub const SCRIPT_TOO_MANY_OPERATIONS: felt252 = 'Too many operations';
    pub const SCRIPT_PUSH_SIZE: felt252 = 'Push value size limit exceeded';
    pub const SCRIPT_NON_CLEAN_STACK: felt252 = 'Non-clean stack after execute';
    pub const SCRIPTNUM_OUT_OF_RANGE: felt252 = 'Scriptnum out of range';
    pub const STACK_OVERFLOW: felt252 = 'Stack overflow';
    pub const STACK_UNDERFLOW: felt252 = 'Stack underflow';
    pub const STACK_OUT_OF_RANGE: felt252 = 'Stack out of range';
    pub const VERIFY_FAILED: felt252 = 'Verify failed';
    pub const OPCODE_RESERVED: felt252 = 'Opcode reserved';
    pub const OPCODE_NOT_IMPLEMENTED: felt252 = 'Opcode not implemented';
    pub const OPCODE_DISABLED: felt252 = 'Opcode is disabled';
    pub const SCRIPT_DISCOURAGE_UPGRADABLE_NOPS: felt252 = 'Upgradable NOPs are discouraged';
    pub const UNSATISFIED_LOCKTIME: felt252 = 'Unsatisfied locktime';
    pub const SCRIPT_STRICT_MULTISIG: felt252 = 'OP_CHECKMULTISIG invalid dummy';
    pub const FINALIZED_TX_CLTV: felt252 = 'Finalized tx in OP_CLTV';
    pub const INVALID_TX_VERSION: felt252 = 'Invalid transaction version';
    pub const SCRIPT_INVALID: felt252 = 'Invalid script data';
    pub const INVALID_COINBASE: felt252 = 'Invalid coinbase transaction';
    pub const SIG_NULLFAIL: felt252 = 'Sig non-zero on failed checksig';
    pub const MINIMAL_DATA: felt252 = 'Opcode represents non-minimal';
    pub const MINIMAL_IF: felt252 = 'If conditional must be 0 or 1';
    pub const DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM: felt252 = 'Upgradable witness program';
    pub const WITNESS_PROGRAM_INVALID: felt252 = 'Invalid witness program';
    pub const WITNESS_PROGRAM_MISMATCH: felt252 = 'Witness program mismatch';
    pub const WITNESS_UNEXPECTED: felt252 = 'Unexpected witness data';
    pub const WITNESS_MALLEATED: felt252 = 'Witness program with sig script';
    pub const WITNESS_MALLEATED_P2SH: felt252 = 'Signature script for p2sh wit';
    pub const WITNESS_PUBKEYTYPE: felt252 = 'Non-compressed key post-segwit';
    pub const WITNESS_PROGRAM_WRONG_LENGTH: felt252 = 'Witness program wrong length';
    pub const WITNESS_PROGRAM_EMPTY: felt252 = 'Empty witness program';
    pub const SCRIPT_TOO_LARGE: felt252 = 'Script is too large';
    pub const INVALID_P2MS: felt252 = 'Invalid P2MS transaction';
    pub const SCRIPT_UNFINISHED: felt252 = 'Script unfinished';
    pub const SCRIPT_ERR_SIG_DER: felt252 = 'Signature DER error';
}

pub fn byte_array_err(err: felt252) -> ByteArray {
    let mut bytes = "";
    let mut word_len = 0;
    let mut byte_shift: u256 = 256;
    while (err.into() / byte_shift) != 0 {
        word_len += 1;
        byte_shift *= 256;
    };
    bytes.append_word(err, word_len);
    bytes
}

// utils.cairo

// Checks if item starts with 0x
// TODO: Check validity of hex?
pub fn is_hex(script_item: @ByteArray) -> bool {
    if script_item.len() < 2 {
        return false;
    }
    let byte_shift = 256;
    let first_two = script_item[0].into() * byte_shift + script_item[1].into();
    first_two == '0x'
}

// Checks if item surrounded with a single or double quote
pub fn is_string(script_item: @ByteArray) -> bool {
    if script_item.len() < 2 {
        return false;
    }
    let single_quote = '\'';
    let double_quote = '"';
    let first = script_item[0];
    let last = script_item[script_item.len() - 1];
    (first == single_quote && last == single_quote)
        || (first == double_quote && last == double_quote)
}

// Check if item is a number (starts with 0-9 or -)
pub fn is_number(script_item: @ByteArray) -> bool {
    if script_item.len() == 0 {
        return false;
    }
    let zero = '0';
    let nine = '9';
    let minus = '-';
    let first = script_item[0];
    if first == minus {
        return script_item.len() > 1;
    }
    if script_item.len() > 1 {
        let second = script_item[1];
        // Some opcodes start with a number; like 2ROT
        return first >= zero && first <= nine && second >= zero && second <= nine;
    }
    first >= zero && first <= nine
}

// byte_array.cairo

// Big-endian
pub fn byte_array_to_felt252_be(byte_array: @ByteArray) -> felt252 {
    let byte_shift = 256;
    let mut value = 0;
    let mut i = 0;
    let byte_array_len = byte_array.len();
    while i != byte_array_len {
        value = value * byte_shift + byte_array[i].into();
        i += 1;
    };
    value
}

// Little-endian
pub fn byte_array_to_felt252_le(byte_array: @ByteArray) -> felt252 {
    let byte_shift = 256;
    let mut value = 0;
    let byte_array_len = byte_array.len();
    let mut i = byte_array_len - 1;
    while true {
        value = value * byte_shift + byte_array[i].into();
        if i == 0 {
            break;
        }
        i -= 1;
    };
    value
}

pub fn byte_array_value_at_be(byte_array: @ByteArray, ref offset: usize, len: usize) -> felt252 {
    let byte_shift = 256;
    let mut value = 0;
    let mut i = offset;
    let end = offset + len;
    while i != end {
        value = value * byte_shift + byte_array[i].into();
        i += 1;
    };
    offset += len;
    value
}

pub fn byte_array_value_at_le(
    byte_array: @ByteArray, ref offset: usize, len: usize
) -> felt252 { // TODO: Bounds check
    let byte_shift = 256;
    let mut value = 0;
    let mut i = offset + len - 1;
    while true {
        value = value * byte_shift + byte_array[i].into();
        if i == offset {
            break;
        }
        i -= 1;
    };
    offset += len;
    value
}

pub fn sub_byte_array(byte_array: @ByteArray, ref offset: usize, len: usize) -> ByteArray {
    let mut sub_byte_array = "";
    let mut i = offset;
    let end = offset + len;
    while i != end {
        sub_byte_array.append_byte(byte_array[i]);
        i += 1;
    };
    offset += len;
    sub_byte_array
}

// TODO: More efficient way to do this
pub fn felt252_to_byte_array(value: felt252) -> ByteArray {
    let byte_shift = 256;
    let mut byte_array = "";
    let mut valueU256: u256 = value.into();
    while valueU256 != 0 {
        let (value_upper, value_lower) = DivRem::div_rem(valueU256, byte_shift);
        byte_array.append_byte(value_lower.try_into().unwrap());
        valueU256 = value_upper;
    };
    byte_array.rev()
}

pub fn u256_from_byte_array_with_offset(arr: @ByteArray, offset: usize, len: usize) -> u256 {
    let total_bytes = arr.len();
    // Return 0 if offset out of bound or len greater than 32 bytes
    if offset >= total_bytes || len > 32 {
        return u256 { high: 0, low: 0 };
    }

    let mut high: u128 = 0;
    let mut low: u128 = 0;
    let mut i: usize = 0;
    let mut high_bytes: usize = 0;

    let available_bytes = total_bytes - offset;
    let read_bytes = if available_bytes < len {
        available_bytes
    } else {
        len
    };

    if read_bytes > 16 {
        high_bytes = read_bytes - 16;
    }
    while i != high_bytes {
        high = high * 256 + arr[i + offset].into();
        i += 1;
    };
    while i != read_bytes {
        low = low * 256 + arr[i + offset].into();
        i += 1;
    };
    u256 { high, low }
}

pub fn byte_array_to_bool(bytes: @ByteArray) -> bool {
    let mut i = 0;
    let mut ret_bool = false;
    let byte_array_len = bytes.len();
    while i != byte_array_len {
        if bytes.at(i).unwrap() != 0 {
            // Can be negative zero
            if i == bytes.len() - 1 && bytes.at(i).unwrap() == 0x80 {
                ret_bool = false;
                break;
            }
            ret_bool = true;
            break;
        }
        i += 1;
    };
    ret_bool
}

// bytecode.cairo

// TODO: little-endian?
// TODO: if odd number of bytes, prepend 0?
pub fn hex_to_bytecode(script_item: @ByteArray) -> ByteArray {
    let half_byte_shift = 16;
    let zero_string = '0';
    let a_string_lower = 'a';
    let a_string_capital = 'A';
    let mut i = 2;
    let mut bytecode = "";
    let script_item_len = script_item.len();
    while i != script_item_len {
        let mut upper_half_byte = 0;
        let mut lower_half_byte = 0;
        if script_item[i] >= a_string_lower {
            upper_half_byte = (script_item[i].into() - a_string_lower + 10) * half_byte_shift;
        } else if script_item[i] >= a_string_capital {
            upper_half_byte = (script_item[i].into() - a_string_capital + 10) * half_byte_shift;
        } else {
            upper_half_byte = (script_item[i].into() - zero_string) * half_byte_shift;
        }
        if script_item[i + 1] >= a_string_lower {
            lower_half_byte = script_item[i + 1].into() - a_string_lower + 10;
        } else if script_item[i + 1] >= a_string_capital {
            lower_half_byte = script_item[i + 1].into() - a_string_capital + 10;
        } else {
            lower_half_byte = script_item[i + 1].into() - zero_string;
        }
        let byte = upper_half_byte + lower_half_byte;
        bytecode.append_byte(byte);
        i += 2;
    };
    bytecode
}

pub fn bytecode_to_hex(bytecode: @ByteArray) -> ByteArray {
    let half_byte_shift = 16;
    let zero = '0';
    let a = 'a';
    let mut hex = "0x";
    let mut i = 0;
    let bytecode_len = bytecode.len();
    if bytecode_len == 0 {
        return "0x00";
    }
    while i != bytecode_len {
        let (upper_half_byte, lower_half_byte) = DivRem::div_rem(bytecode[i], half_byte_shift);
        let upper_half: u8 = if upper_half_byte < 10 {
            upper_half_byte + zero
        } else {
            upper_half_byte - 10 + a
        };
        let lower_half: u8 = if lower_half_byte < 10 {
            lower_half_byte + zero
        } else {
            lower_half_byte - 10 + a
        };
        hex.append_byte(upper_half);
        hex.append_byte(lower_half);
        i += 1;
    };
    hex
}

pub fn int_size_in_bytes(u_32: u32) -> u32 {
    let mut value: u32 = u_32;
    let mut size = 0;

    while value != 0 {
        size += 1;
        value /= 256;
    };
    if size == 0 {
        size = 1;
    }
    size
}

pub fn var_int_size(buf: @ByteArray, mut offset: u32) -> u32 {
    let discriminant = byte_array_value_at_le(buf, ref offset, 1);
    if discriminant == 0xff {
        return 8;
    } else if discriminant == 0xfe {
        return 4;
    } else if discriminant == 0xfd {
        return 2;
    } else {
        return 1;
    }
}

pub fn read_var_int(buf: @ByteArray, ref offset: u32) -> u64 {
    // TODO: Error handling
    let discriminant: u64 = byte_array_value_at_le(buf, ref offset, 1).try_into().unwrap();
    if discriminant == 0xff {
        return byte_array_value_at_le(buf, ref offset, 8).try_into().unwrap();
    } else if discriminant == 0xfe {
        return byte_array_value_at_le(buf, ref offset, 4).try_into().unwrap();
    } else if discriminant == 0xfd {
        return byte_array_value_at_le(buf, ref offset, 2).try_into().unwrap();
    } else {
        return discriminant;
    }
}

pub fn write_var_int(ref buf: ByteArray, value: u64) {
    if value < 0xfd {
        buf.append_byte(value.try_into().unwrap());
    } else if value < 0x10000 {
        buf.append_byte(0xfd);
        buf.append_word_rev(value.into(), 2);
    } else if value < 0x100000000 {
        buf.append_byte(0xfe);
        buf.append_word_rev(value.into(), 4);
    } else {
        buf.append_byte(0xff);
        buf.append_word_rev(value.into(), 8);
    }
}

// Scriptnum.cairo

// Wrapper around Bitcoin Script 'sign-magnitude' 4 byte integer.
pub mod ScriptNum {

    // Errors.cairo

pub mod Error {
    pub const SCRIPT_FAILED: felt252 = 'Script failed after execute';
    pub const SCRIPT_EMPTY_STACK: felt252 = 'Stack empty after execute';
    pub const SCRIPT_UNBALANCED_CONDITIONAL_STACK: felt252 = 'Unbalanced conditional';
    pub const SCRIPT_TOO_MANY_OPERATIONS: felt252 = 'Too many operations';
    pub const SCRIPT_PUSH_SIZE: felt252 = 'Push value size limit exceeded';
    pub const SCRIPT_NON_CLEAN_STACK: felt252 = 'Non-clean stack after execute';
    pub const SCRIPTNUM_OUT_OF_RANGE: felt252 = 'Scriptnum out of range';
    pub const STACK_OVERFLOW: felt252 = 'Stack overflow';
    pub const STACK_UNDERFLOW: felt252 = 'Stack underflow';
    pub const STACK_OUT_OF_RANGE: felt252 = 'Stack out of range';
    pub const VERIFY_FAILED: felt252 = 'Verify failed';
    pub const OPCODE_RESERVED: felt252 = 'Opcode reserved';
    pub const OPCODE_NOT_IMPLEMENTED: felt252 = 'Opcode not implemented';
    pub const OPCODE_DISABLED: felt252 = 'Opcode is disabled';
    pub const SCRIPT_DISCOURAGE_UPGRADABLE_NOPS: felt252 = 'Upgradable NOPs are discouraged';
    pub const UNSATISFIED_LOCKTIME: felt252 = 'Unsatisfied locktime';
    pub const SCRIPT_STRICT_MULTISIG: felt252 = 'OP_CHECKMULTISIG invalid dummy';
    pub const FINALIZED_TX_CLTV: felt252 = 'Finalized tx in OP_CLTV';
    pub const INVALID_TX_VERSION: felt252 = 'Invalid transaction version';
    pub const SCRIPT_INVALID: felt252 = 'Invalid script data';
    pub const INVALID_COINBASE: felt252 = 'Invalid coinbase transaction';
    pub const SIG_NULLFAIL: felt252 = 'Sig non-zero on failed checksig';
    pub const MINIMAL_DATA: felt252 = 'Opcode represents non-minimal';
    pub const MINIMAL_IF: felt252 = 'If conditional must be 0 or 1';
    pub const DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM: felt252 = 'Upgradable witness program';
    pub const WITNESS_PROGRAM_INVALID: felt252 = 'Invalid witness program';
    pub const WITNESS_PROGRAM_MISMATCH: felt252 = 'Witness program mismatch';
    pub const WITNESS_UNEXPECTED: felt252 = 'Unexpected witness data';
    pub const WITNESS_MALLEATED: felt252 = 'Witness program with sig script';
    pub const WITNESS_MALLEATED_P2SH: felt252 = 'Signature script for p2sh wit';
    pub const WITNESS_PUBKEYTYPE: felt252 = 'Non-compressed key post-segwit';
    pub const WITNESS_PROGRAM_WRONG_LENGTH: felt252 = 'Witness program wrong length';
    pub const WITNESS_PROGRAM_EMPTY: felt252 = 'Empty witness program';
    pub const SCRIPT_TOO_LARGE: felt252 = 'Script is too large';
    pub const INVALID_P2MS: felt252 = 'Invalid P2MS transaction';
    pub const SCRIPT_UNFINISHED: felt252 = 'Script unfinished';
    pub const SCRIPT_ERR_SIG_DER: felt252 = 'Signature DER error';
}

pub fn byte_array_err(err: felt252) -> ByteArray {
    let mut bytes = "";
    let mut word_len = 0;
    let mut byte_shift: u256 = 256;
    while (err.into() / byte_shift) != 0 {
        word_len += 1;
        byte_shift *= 256;
    };
    bytes.append_word(err, word_len);
    bytes
}
    
    const BYTESHIFT: i64 = 256;
    const MAX_INT32: i32 = 2147483647;
    const MIN_INT32: i32 = -2147483647;

    fn check_minimal_data(input: @ByteArray) -> Result<(), felt252> {
        if input.len() == 0 {
            return Result::Ok(());
        }

        let last_element = input.at(input.len() - 1).unwrap();
        if last_element & 0x7F == 0 {
            if input.len() == 1 || input.at(input.len() - 2).unwrap() & 0x80 == 0 {
                return Result::Err(Error::MINIMAL_DATA);
            }
        }

        return Result::Ok(());
    }

    // Wrap i64 with a maximum size of 4 bytes. Can result in 5 byte array.
    pub fn wrap(mut input: i64) -> ByteArray {
        if input == 0 {
            return "";
        }

        // TODO
        // if input > MAX_INT32.into() || input < MIN_INT32.into() {
        //     return Result::Err(Error::SCRIPTNUM_OUT_OF_RANGE);
        // }

        let mut result: ByteArray = Default::default();
        let is_negative = {
            if input < 0 {
                input *= -1;
                true
            } else {
                false
            }
        };
        let unsigned: u64 = input.try_into().unwrap();
        let bytes_len: usize = integer_bytes_len(input.into());
        result.append_word_rev(unsigned.into(), bytes_len - 1);
        // Compute 'sign-magnitude' byte.
        let sign_byte: u8 = get_last_byte_of_uint(unsigned);
        if is_negative {
            if (sign_byte > 127) {
                result.append_byte(sign_byte);
                result.append_byte(128);
            } else {
                result.append_byte(sign_byte + 128);
            }
        } else {
            if (sign_byte > 127) {
                result.append_byte(sign_byte);
                result.append_byte(0);
            } else {
                result.append_byte(sign_byte);
            }
        }
        result
    }

    // Unwrap sign-magnitude encoded ByteArray into a 4 byte int maximum.
    pub fn try_into_num(input: ByteArray, minimal_required: bool) -> Result<i64, felt252> {
        let mut result: i64 = 0;
        let mut i: u32 = 0;
        let mut multiplier: i64 = 1;
        if minimal_required {
            check_minimal_data(@input)?;
        }

        if input.len() == 0 {
            return Result::Ok(0);
        }
        let snap_input = @input;
        let end = snap_input.len() - 1;
        while i != end {
            result += snap_input.at(i).unwrap().into() * multiplier;
            multiplier *= BYTESHIFT;
            i += 1;
        };
        // Recover value and sign from 'sign-magnitude' byte.
        let sign_byte: i64 = input.at(i).unwrap().into();
        if sign_byte >= 128 {
            result = (multiplier * (sign_byte - 128) * -1) - result;
        } else {
            result += sign_byte * multiplier;
        }
        if result > MAX_INT32.into() || result < MIN_INT32.into() {
            return Result::Err(Error::SCRIPTNUM_OUT_OF_RANGE);
        }
        Result::Ok(result)
    }

    pub fn into_num(input: ByteArray) -> i64 {
        try_into_num(input, false).unwrap()
    }

    pub fn unwrap(input: ByteArray) -> i64 {
        try_into_num(input, false).unwrap()
    }

    // Unwrap 'n' byte of sign-magnitude encoded ByteArray.
    pub fn try_into_num_n_bytes(
        input: ByteArray, n: usize, minimal_required: bool
    ) -> Result<i64, felt252> {
        let mut result: i64 = 0;
        let mut i: u32 = 0;
        let mut multiplier: i64 = 1;
        if minimal_required {
            check_minimal_data(@input)?;
        }
        if input.len() == 0 {
            return Result::Ok(0);
        }
        let snap_input = @input;
        let end = snap_input.len() - 1;
        while i != end {
            result += snap_input.at(i).unwrap().into() * multiplier;
            multiplier *= BYTESHIFT;
            i += 1;
        };
        // Recover value and sign from 'sign-magnitude' byte.
        let sign_byte: i64 = input.at(i).unwrap().into();
        if sign_byte >= 128 {
            result = (multiplier * (sign_byte - 128) * -1) - result;
        } else {
            result += sign_byte * multiplier;
        }
        if integer_bytes_len(result.into()) > n {
            return Result::Err(Error::SCRIPTNUM_OUT_OF_RANGE);
        }
        return Result::Ok(result);
    }

    pub fn into_num_n_bytes(input: ByteArray, n: usize) -> i64 {
        try_into_num_n_bytes(input, n, false).unwrap()
    }

    pub fn unwrap_n(input: ByteArray, n: usize) -> i64 {
        try_into_num_n_bytes(input, n, false).unwrap()
    }

    // Return the minimal number of byte to represent 'value'.
    fn integer_bytes_len(mut value: i128) -> usize {
        if value < 0 {
            value *= -1;
        }
        let mut power_byte = BYTESHIFT.try_into().unwrap();
        let mut bytes_len: usize = 1;
        while value >= power_byte {
            bytes_len += 1;
            power_byte *= 256;
        };
        bytes_len
    }

    // Return the value of the last byte of 'value'.
    fn get_last_byte_of_uint(mut value: u64) -> u8 {
        let byteshift = BYTESHIFT.try_into().unwrap();
        while value > byteshift {
            value = value / byteshift;
        };
        value.try_into().unwrap()
    }

    // Return i64 as an i32 within range [-2^31, 2^31 - 1].
    pub fn to_int32(mut n: i64) -> i32 {
        if n > MAX_INT32.into() {
            return MAX_INT32;
        }

        if n < MIN_INT32.into() {
            return MIN_INT32;
        }

        return n.try_into().unwrap();
    }
}

// cond_stack.cairo

#[derive(Destruct)]
pub struct ConditionalStack {
    stack: Felt252Dict<u8>,
    len: usize,
}

#[generate_trait()]
pub impl ConditionalStackImpl of ConditionalStackTrait {
    fn new() -> ConditionalStack {
        ConditionalStack { stack: Default::default(), len: 0, }
    }

    fn push(ref self: ConditionalStack, value: u8) {
        self.stack.insert(self.len.into(), value);
        self.len += 1;
    }

    fn pop(ref self: ConditionalStack) -> Result<(), felt252> {
        if self.len == 0 {
            return Result::Err('pop: conditional stack is empty');
        }
        self.len -= 1;
        return Result::Ok(());
    }

    fn branch_executing(ref self: ConditionalStack) -> bool {
        if self.len == 0 {
            return true;
        } else {
            return self.stack[self.len.into() - 1] == 1;
        }
    }

    fn len(ref self: ConditionalStack) -> usize {
        self.len
    }

    fn swap_condition(ref self: ConditionalStack) {
        let cond_idx = self.len() - 1;
        match self.stack.get(cond_idx.into()) {
            0 => self.stack.insert(cond_idx.into(), 1),
            1 => self.stack.insert(cond_idx.into(), 0),
            2 => self.stack.insert(cond_idx.into(), 2),
            _ => panic!("Invalid condition")
        }
    }
}

// parser.cairo

// Returns true if the script is a script hash
pub fn is_script_hash(script_pubkey: @ByteArray) -> bool {
    if script_pubkey.len() == 23
        && script_pubkey[0] == Opcode::OP_HASH160
        && script_pubkey[1] == Opcode::OP_DATA_20
        && script_pubkey[22] == Opcode::OP_EQUAL {
        return true;
    }
    return false;
}


// Returns true if the script sig is push only
pub fn is_push_only(script: @ByteArray) -> bool {
    let mut i = 0;
    let mut is_push_only = true;
    let script_len = script.len();
    while i != script_len {
        // TODO: Error handling if i outside bounds
        let opcode = script[i];
        if opcode > Opcode::OP_16 {
            is_push_only = false;
            break;
        }

        // TODO: Error handling
        let data_len = data_len(script, i).unwrap();
        i += data_len + 1;
    };
    return is_push_only;
}

// Returns the data in the script at the given index
pub fn data_at(script: @ByteArray, mut idx: usize, len: usize) -> Result<ByteArray, felt252> {
    let mut data = "";
    let mut end = idx + len;
    if end > script.len() {
        return Result::Err(Error::SCRIPT_INVALID);
    }
    while idx != end {
        data.append_byte(script[idx]);
        idx += 1;
    };
    return Result::Ok(data);
}

// Returns the length of all the data associated with the opcode at the given index
pub fn data_len(script: @ByteArray, idx: usize) -> Result<usize, felt252> {
    let opcode: u8 = script[idx];
    if Opcode::is_data_opcode(opcode) {
        return Result::Ok(opcode.into());
    }
    let mut push_data_len = 0;
    if opcode == Opcode::OP_PUSHDATA1 {
        push_data_len = 1;
    } else if opcode == Opcode::OP_PUSHDATA2 {
        push_data_len = 2;
    } else if opcode == Opcode::OP_PUSHDATA4 {
        push_data_len = 4;
    } else {
        return Result::Ok(0);
    }
    return Result::Ok(
        byte_array_to_felt252_le(@data_at(script, idx + 1, push_data_len)?).try_into().unwrap()
            + push_data_len
    );
}

// Returns the length of the data associated with the push data opcode at the given index
pub fn push_data_len(script: @ByteArray, idx: usize) -> Result<usize, felt252> {
    let mut len = 0;
    let opcode: u8 = script[idx];
    if opcode == Opcode::OP_PUSHDATA1 {
        len = 1;
    } else if opcode == Opcode::OP_PUSHDATA2 {
        len = 2;
    } else if opcode == Opcode::OP_PUSHDATA4 {
        len = 4;
    } else {
        return Result::Err(Error::SCRIPT_INVALID);
    }

    return Result::Ok(
        byte_array_to_felt252_le(@data_at(script, idx + 1, len)?).try_into().unwrap()
    );
}

// Return the next opcode_idx in the script
pub fn next(script: @ByteArray, idx: usize) -> Result<usize, felt252> {
    let data_len = data_len(script, idx)?;
    return Result::Ok(idx + data_len + 1);
}

// flags.cairo

#[derive(Copy, Drop)]
pub enum ScriptFlags {
    // ScriptBip16, allows P2SH transactions.
    ScriptBip16,
    // ScriptStrictMultiSig, CHECKMULTISIG stack item must be zero length.
    ScriptStrictMultiSig,
    // ScriptDiscourageUpgradableNops, reserves NOP1-NOP10.
    ScriptDiscourageUpgradableNops,
    // ScriptVerifyCheckLockTimeVerify, enforces locktime (BIP0065).
    ScriptVerifyCheckLockTimeVerify,
    // ScriptVerifyCheckSequenceVerify, restricts by output age (BIP0112).
    ScriptVerifyCheckSequenceVerify,
    // ScriptVerifyCleanStack, ensures one true element on stack.
    ScriptVerifyCleanStack,
    // ScriptVerifyDERSignatures, requires DER-formatted signatures.
    ScriptVerifyDERSignatures,
    // ScriptVerifyLowS, requires S <= order / 2.
    ScriptVerifyLowS,
    // ScriptVerifyMinimalData, uses minimal data pushes.
    ScriptVerifyMinimalData,
    // ScriptVerifyNullFail, requires empty signatures on failure.
    ScriptVerifyNullFail,
    // ScriptVerifySigPushOnly, allows only pushed data.
    ScriptVerifySigPushOnly,
    // ScriptVerifyStrictEncoding, enforces strict encoding.
    ScriptVerifyStrictEncoding,
    // ScriptVerifyWitness, verifies with witness programs.
    ScriptVerifyWitness,
    // ScriptVerifyDiscourageUpgradeableWitnessProgram, non-standard witness versions 2-16.
    ScriptVerifyDiscourageUpgradeableWitnessProgram,
    // ScriptVerifyMinimalIf, requires empty vector or [0x01] for OP_IF/OP_NOTIF.
    ScriptVerifyMinimalIf,
    // ScriptVerifyWitnessPubKeyType, requires compressed public keys.
    ScriptVerifyWitnessPubKeyType,
    // ScriptVerifyTaproot, verifies using taproot rules.
    ScriptVerifyTaproot,
    // ScriptVerifyDiscourageUpgradeableTaprootVersion, non-standard unknown taproot versions.
    ScriptVerifyDiscourageUpgradeableTaprootVersion,
    // ScriptVerifyDiscourageOpSuccess, non-standard OP_SUCCESS codes.
    ScriptVerifyDiscourageOpSuccess,
    // ScriptVerifyDiscourageUpgradeablePubkeyType, non-standard unknown pubkey versions.
    ScriptVerifyDiscourageUpgradeablePubkeyType,
    // ScriptVerifyConstScriptCode, fails if signature match in script code.
    ScriptVerifyConstScriptCode,
}

impl ScriptFlagsIntoU32 of Into<ScriptFlags, u32> {
    fn into(self: ScriptFlags) -> u32 {
        match self {
            ScriptFlags::ScriptBip16 => 0x1,
            ScriptFlags::ScriptStrictMultiSig => 0x2,
            ScriptFlags::ScriptDiscourageUpgradableNops => 0x4,
            ScriptFlags::ScriptVerifyCheckLockTimeVerify => 0x8,
            ScriptFlags::ScriptVerifyCheckSequenceVerify => 0x10,
            ScriptFlags::ScriptVerifyCleanStack => 0x20,
            ScriptFlags::ScriptVerifyDERSignatures => 0x40,
            ScriptFlags::ScriptVerifyLowS => 0x80,
            ScriptFlags::ScriptVerifyMinimalData => 0x100,
            ScriptFlags::ScriptVerifyNullFail => 0x200,
            ScriptFlags::ScriptVerifySigPushOnly => 0x400,
            ScriptFlags::ScriptVerifyStrictEncoding => 0x800,
            ScriptFlags::ScriptVerifyWitness => 0x1000,
            ScriptFlags::ScriptVerifyDiscourageUpgradeableWitnessProgram => 0x2000,
            ScriptFlags::ScriptVerifyMinimalIf => 0x4000,
            ScriptFlags::ScriptVerifyWitnessPubKeyType => 0x8000,
            ScriptFlags::ScriptVerifyTaproot => 0x10000,
            ScriptFlags::ScriptVerifyDiscourageUpgradeableTaprootVersion => 0x20000,
            ScriptFlags::ScriptVerifyDiscourageOpSuccess => 0x40000,
            ScriptFlags::ScriptVerifyDiscourageUpgradeablePubkeyType => 0x80000,
            ScriptFlags::ScriptVerifyConstScriptCode => 0x100000,
        }
    }
}

fn flag_from_string(flag: felt252) -> u32 {
    // TODO: To map and remaining flags
    if flag == 'P2SH' {
        return ScriptFlags::ScriptBip16.into();
    } else if flag == 'STRICTENC' {
        return ScriptFlags::ScriptVerifyStrictEncoding.into();
    } else if flag == 'MINIMALDATA' {
        return ScriptFlags::ScriptVerifyMinimalData.into();
    } else if flag == 'DISCOURAGE_UPGRADABLE_NOPS' {
        return ScriptFlags::ScriptDiscourageUpgradableNops.into();
    } else if flag == 'DERSIG' {
        return ScriptFlags::ScriptVerifyDERSignatures.into();
    } else if flag == 'WITNESS' {
        return ScriptFlags::ScriptVerifyWitness.into();
    } else if flag == 'LOW_S' {
        return ScriptFlags::ScriptVerifyLowS.into();
    } else if flag == 'NULLDUMMY' {
        // TODO: Double check this
        return ScriptFlags::ScriptStrictMultiSig.into();
    } else if flag == 'NULLFAIL' {
        return ScriptFlags::ScriptVerifyNullFail.into();
    } else if flag == 'SIGPUSHONLY' {
        return ScriptFlags::ScriptVerifySigPushOnly.into();
    } else if flag == 'CLEANSTACK' {
        return ScriptFlags::ScriptVerifyCleanStack.into();
    } else if flag == 'DISCOURAGE_UPGRADABLE_WITNESS' {
        return ScriptFlags::ScriptVerifyDiscourageUpgradeableWitnessProgram.into();
    } else if flag == 'WITNESS_PUBKEYTYPE' {
        return ScriptFlags::ScriptVerifyWitnessPubKeyType.into();
    } else if flag == 'MINIMALIF' {
        return ScriptFlags::ScriptVerifyMinimalIf.into();
    } else if flag == 'CHECKSEQUENCEVERIFY' {
        return ScriptFlags::ScriptVerifyCheckSequenceVerify.into();
    } else {
        return 0;
    }
}

pub fn parse_flags(flags: ByteArray) -> u32 {
    let mut script_flags: u32 = 0;

    // Split the flags string by commas.
    let seperator = ',';
    let mut split_flags: Array<ByteArray> = array![];
    let mut current = "";
    let mut i = 0;
    let flags_len = flags.len();
    while i != flags_len {
        let char = flags[i].into();
        if char == seperator {
            if current == "" {
                i += 1;
                continue;
            }
            split_flags.append(current);
            current = "";
        } else {
            current.append_byte(char);
        }
        i += 1;
    };
    // Handle the last flag.
    if current != "" {
        split_flags.append(current);
    }

    // Compile the flags into a single integer.
    let mut i = 0;
    let flags_len = split_flags.len();
    while i != flags_len {
        let flag = split_flags.at(i);
        let flag_value = flag_from_string(byte_array_to_felt252_be(flag));
        script_flags += flag_value;
        i += 1;
    };

    script_flags
}

// stack.cairo

#[derive(Destruct)]
pub struct ScriptStack {
    data: Felt252Dict<Nullable<ByteArray>>,
    len: usize,
    pub verify_minimal_data: bool,
}

#[generate_trait()]
pub impl ScriptStackImpl of ScriptStackTrait {
    fn new() -> ScriptStack {
        ScriptStack { data: Default::default(), len: 0, verify_minimal_data: false }
    }

    fn push_byte_array(ref self: ScriptStack, value: ByteArray) {
        self.data.insert(self.len.into(), NullableTrait::new(value));
        self.len += 1;
    }

    fn push_int(ref self: ScriptStack, value: i64) {
        let bytes = ScriptNum::wrap(value);
        self.push_byte_array(bytes);
    }

    fn push_bool(ref self: ScriptStack, value: bool) {
        if value {
            let mut v: ByteArray = Default::default();
            v.append_byte(1);
            self.push_byte_array(v);
        } else {
            self.push_byte_array(Default::default());
        }
    }

    fn pop_byte_array(ref self: ScriptStack) -> Result<ByteArray, felt252> {
        if self.len == 0 {
            return Result::Err(Error::STACK_UNDERFLOW);
        }
        self.len -= 1;
        let (entry, bytes) = self.data.entry(self.len.into());
        self.data = entry.finalize(NullableTrait::new(""));
        return Result::Ok(bytes.deref());
    }

    fn pop_int(ref self: ScriptStack) -> Result<i64, felt252> {
        let value = self.pop_byte_array()?;
        return Result::Ok(ScriptNum::try_into_num(value, self.verify_minimal_data)?);
    }

    fn pop_bool(ref self: ScriptStack) -> Result<bool, felt252> {
        let bytes = self.pop_byte_array()?;
        return Result::Ok(byte_array_to_bool(@bytes));
    }

    fn peek_byte_array(ref self: ScriptStack, idx: usize) -> Result<ByteArray, felt252> {
        if idx >= self.len {
            return Result::Err(Error::STACK_OUT_OF_RANGE);
        }
        let (entry, bytes) = self.data.entry((self.len - idx - 1).into());
        let bytes = bytes.deref();
        self.data = entry.finalize(NullableTrait::new(bytes.clone()));
        return Result::Ok(bytes);
    }

    fn peek_int(ref self: ScriptStack, idx: usize) -> Result<i64, felt252> {
        let bytes = self.peek_byte_array(idx)?;
        return Result::Ok(ScriptNum::try_into_num(bytes, self.verify_minimal_data)?);
    }

    fn peek_bool(ref self: ScriptStack, idx: usize) -> Result<bool, felt252> {
        let bytes = self.peek_byte_array(idx)?;
        return Result::Ok(byte_array_to_bool(@bytes));
    }

    fn len(ref self: ScriptStack) -> usize {
        self.len
    }

    fn depth(ref self: ScriptStack) -> usize {
        self.len
    }

    fn print_element(ref self: ScriptStack, idx: usize) {
        let (entry, arr) = self.data.entry(idx.into());
        let arr = arr.deref();
        if arr.len() == 0 {
            println!("stack[{}]: null", idx);
        } else {
            println!("stack[{}]: {}", idx, bytecode_to_hex(@arr.clone()));
        }
        self.data = entry.finalize(NullableTrait::new(arr));
    }

    fn print(ref self: ScriptStack) {
        let mut i = self.len;
        while i != 0 {
            i -= 1;
            self.print_element(i.into());
        }
    }

    fn json(ref self: ScriptStack) {
        let mut i = 0;
        print!("[");
        let end = self.len;
        while i != end {
            let (entry, arr) = self.data.entry(i.into());
            let arr = arr.deref();
            print!("\"{}\"", bytecode_to_hex(@arr.clone()));
            self.data = entry.finalize(NullableTrait::new(arr));
            if i < end - 1 {
                print!(",");
            }
            i += 1;
        };
        println!("]");
    }

    fn rot_n(ref self: ScriptStack, n: u32) -> Result<(), felt252> {
        if n < 1 {
            return Result::Err('rot_n: invalid n value');
        }
        let mut err = '';
        let entry_index = 3 * n - 1;
        let mut i = n;
        while i != 0 {
            let res = self.nip_n(entry_index);
            if res.is_err() {
                err = res.unwrap_err();
                break;
            }
            self.push_byte_array(res.unwrap());
            i -= 1;
        };
        if err != '' {
            return Result::Err(err);
        }
        return Result::Ok(());
    }

    fn stack_to_span(ref self: ScriptStack) -> Span<ByteArray> {
        let mut result = array![];
        let mut i = 0;
        let end = self.len;
        while i != end {
            let (entry, arr) = self.data.entry(i.into());
            let arr = arr.deref();
            result.append(arr.clone());
            self.data = entry.finalize(NullableTrait::new(arr));
            i += 1
        };

        return result.span();
    }

    fn dup_n(ref self: ScriptStack, n: u32) -> Result<(), felt252> {
        if (n < 1) {
            return Result::Err('dup_n: invalid n value');
        }
        let mut i = n;
        let mut err = '';
        while i != 0 {
            i -= 1;
            let value = self.peek_byte_array(n - 1);
            if value.is_err() {
                err = value.unwrap_err();
                break;
            }
            self.push_byte_array(value.unwrap());
        };
        if err != '' {
            return Result::Err(err);
        }
        return Result::Ok(());
    }

    fn tuck(ref self: ScriptStack) -> Result<(), felt252> {
        let top_element = self.pop_byte_array()?;
        let next_element = self.pop_byte_array()?;

        self.push_byte_array(top_element.clone());
        self.push_byte_array(next_element);
        self.push_byte_array(top_element);
        return Result::Ok(());
    }

    fn nip_n(ref self: ScriptStack, idx: usize) -> Result<ByteArray, felt252> {
        let value = self.peek_byte_array(idx)?;

        // Shift all elements above idx down by one
        let mut i = 0;
        while i != idx {
            let next_value = self.peek_byte_array(idx - i - 1).unwrap();
            let (entry, _) = self.data.entry((self.len - idx + i - 1).into());
            self.data = entry.finalize(NullableTrait::new(next_value));
            i += 1;
        };
        let (last_entry, _) = self.data.entry((self.len - 1).into());
        self.data = last_entry.finalize(NullableTrait::new(""));
        self.len -= 1;
        return Result::Ok(value);
    }

    fn pick_n(ref self: ScriptStack, idx: i32) -> Result<(), felt252> {
        if idx < 0 {
            return Result::Err(Error::STACK_OUT_OF_RANGE);
        }

        let idxU32: u32 = idx.try_into().unwrap();
        if idxU32 >= self.len {
            return Result::Err(Error::STACK_OUT_OF_RANGE);
        }

        let so = self.peek_byte_array(idxU32)?;

        self.push_byte_array(so);
        return Result::Ok(());
    }

    fn roll_n(ref self: ScriptStack, n: i32) -> Result<(), felt252> {
        if n < 0 {
            return Result::Err(Error::STACK_OUT_OF_RANGE);
        }
        let nU32: u32 = n.try_into().unwrap();
        if nU32 >= self.len {
            return Result::Err(Error::STACK_OUT_OF_RANGE);
        }

        let value = self.nip_n(nU32)?;
        self.push_byte_array(value);
        return Result::Ok(());
    }

    fn over_n(ref self: ScriptStack, mut n: u32) -> Result<(), felt252> {
        if n < 1 {
            return Result::Err('over_n: invalid n value');
        }
        let entry: u32 = (2 * n) - 1;
        let mut err = '';
        while n != 0 {
            let res = self.peek_byte_array(entry);
            if res.is_err() {
                err = res.unwrap_err();
                break;
            }

            self.push_byte_array(res.unwrap());
            n -= 1;
        };

        if err != '' {
            return Result::Err(err);
        }

        return Result::Ok(());
    }

    // Set stack to a new array of byte arrays
    fn set_stack(ref self: ScriptStack, stack: Span<ByteArray>, start: u32, len: u32) {
        self.data = Default::default();
        self.len = 0;
        let mut i = start;
        let end = start + len;
        while i != end {
            self.push_byte_array(stack.at(i).clone());
            i += 1;
        };
    }
}

// hash.cairo

use core::sha256::compute_sha256_byte_array;

pub fn sha256_byte_array(byte: @ByteArray) -> ByteArray {
    let msg_hash = compute_sha256_byte_array(byte);
    let mut hash_value: ByteArray = "";
    for word in msg_hash.span() {
        hash_value.append_word((*word).into(), 4);
    };

    hash_value
}

pub fn double_sha256_bytearray(byte: @ByteArray) -> ByteArray {
    return sha256_byte_array(@sha256_byte_array(byte));
}

pub fn double_sha256(byte: @ByteArray) -> u256 {
    let msg_hash = compute_sha256_byte_array(byte);
    let mut res_bytes = "";
    for word in msg_hash.span() {
        res_bytes.append_word((*word).into(), 4);
    };
    let msg_hash = compute_sha256_byte_array(@res_bytes);
    let mut hash_value: u256 = 0;
    for word in msg_hash
        .span() {
            hash_value *= 0x100000000;
            hash_value = hash_value + (*word).into();
        };

    hash_value
}

// math.cairo

use core::num::traits::{Zero, One};

// Fast exponentiation using the square-and-multiply algorithm
pub fn fast_power<
    T,
    U,
    +Zero<T>,
    +Zero<U>,
    +One<T>,
    +One<U>,
    +Add<U>,
    +Mul<T>,
    +Rem<U>,
    +Div<U>,
    +Copy<T>,
    +Copy<U>,
    +Drop<T>,
    +Drop<U>,
    +PartialEq<U>,
>(
    base: T, exp: U
) -> T {
    if exp == Zero::zero() {
        return One::one();
    }

    let mut res: T = One::one();
    let mut base: T = base;
    let mut exp: U = exp;

    let two: U = One::one() + One::one();

    loop {
        if exp % two == One::one() {
            res = res * base;
        }
        exp = exp / two;
        if exp == Zero::zero() {
            break res;
        }
        base = base * base;
    }
}

// bit_shifts.cairo

use core::num::traits::{ BitSize };

/// Performs a bitwise right shift on the given value by a specified number of bits.
pub fn shr<
    T,
    U,
    +Zero<T>,
    +Zero<U>,
    +One<T>,
    +One<U>,
    +Add<T>,
    +Add<U>,
    +Sub<U>,
    +Div<T>,
    +Mul<T>,
    +Div<U>,
    +Rem<U>,
    +Copy<T>,
    +Copy<U>,
    +Drop<T>,
    +Drop<U>,
    +PartialOrd<U>,
    +PartialEq<U>,
    +BitSize<T>,
    +Into<usize, U>
>(
    self: T, shift: U
) -> T {
    if shift > BitSize::<T>::bits().try_into().unwrap() - One::one() {
        return Zero::zero();
    }

    let two = One::one() + One::one();
    self / fast_power(two, shift)
}

/// Performs a bitwise left shift on the given value by a specified number of bits.
pub fn shl<
    T,
    U,
    +Zero<T>,
    +Zero<U>,
    +One<T>,
    +One<U>,
    +Add<T>,
    +Add<U>,
    +Sub<U>,
    +Mul<T>,
    +Div<U>,
    +Rem<U>,
    +Copy<T>,
    +Copy<U>,
    +Drop<T>,
    +Drop<U>,
    +PartialOrd<U>,
    +PartialEq<U>,
    +BitSize<T>,
    +Into<usize, U>
>(
    self: T, shift: U,
) -> T {
    if shift > BitSize::<T>::bits().into() - One::one() {
        return Zero::zero();
    }
    let two = One::one() + One::one();
    self * fast_power(two, shift)
}

// transaction.cairo

// Tracks previous transaction outputs
#[derive(Drop, Copy)]
pub struct EngineOutPoint {
    pub txid: u256,
    pub vout: u32,
}

#[derive(Drop, Clone)]
pub struct EngineTransactionInput {
    pub previous_outpoint: EngineOutPoint,
    pub signature_script: ByteArray,
    pub witness: Array<ByteArray>,
    pub sequence: u32,
}

#[derive(Drop, Clone)]
pub struct EngineTransactionOutput {
    pub value: i64,
    pub publickey_script: ByteArray,
}

// TODO: Move these EngineTransaction structs to the testing dir after
// signature::transaction_procedure cleanup
#[derive(Drop, Clone)]
pub struct EngineTransaction {
    pub version: i32,
    pub transaction_inputs: Array<EngineTransactionInput>,
    pub transaction_outputs: Array<EngineTransactionOutput>,
    pub locktime: u32,
}

pub trait EngineInternalTransactionTrait {
    fn new(
        version: i32,
        transaction_inputs: Array<EngineTransactionInput>,
        transaction_outputs: Array<EngineTransactionOutput>,
        locktime: u32
    ) -> EngineTransaction;
    fn new_signed(script_sig: ByteArray, pubkey_script: ByteArray) -> EngineTransaction;
    fn new_signed_witness(
        script_sig: ByteArray, pubkey_script: ByteArray, witness: Array<ByteArray>, value: i64
    ) -> EngineTransaction;
    fn btc_decode(raw: ByteArray, encoding: u32) -> EngineTransaction;
    fn deserialize(raw: ByteArray) -> EngineTransaction;
    fn deserialize_no_witness(raw: ByteArray) -> EngineTransaction;
    fn btc_encode(self: EngineTransaction, encoding: u32) -> ByteArray;
    fn serialize(self: EngineTransaction) -> ByteArray;
    fn serialize_no_witness(self: EngineTransaction) -> ByteArray;
    fn calculate_block_subsidy(block_height: u32) -> i64;
    fn is_coinbase(self: @EngineTransaction) -> bool;
    fn validate_coinbase(
        self: EngineTransaction, block_height: u32, total_fees: i64
    ) -> Result<(), felt252>;
    fn print(self: @EngineTransaction);
}

pub const BASE_ENCODING: u32 = 0x01;
pub const WITNESS_ENCODING: u32 = 0x02;

pub impl EngineInternalTransactionImpl of EngineInternalTransactionTrait {
    fn new(
        version: i32,
        transaction_inputs: Array<EngineTransactionInput>,
        transaction_outputs: Array<EngineTransactionOutput>,
        locktime: u32
    ) -> EngineTransaction {
        EngineTransaction {
            version: version,
            transaction_inputs: transaction_inputs,
            transaction_outputs: transaction_outputs,
            locktime: locktime,
        }
    }

    fn new_signed(script_sig: ByteArray, pubkey_script: ByteArray) -> EngineTransaction {
        let coinbase_tx_inputs = array![
            EngineTransactionInput {
                previous_outpoint: EngineOutPoint { txid: 0x0, vout: 0xffffffff, },
                signature_script: "\x00\x00",
                witness: array![],
                sequence: 0xffffffff,
            }
        ];
        let coinbase_tx_outputs = array![
            EngineTransactionOutput { value: 0, publickey_script: pubkey_script, }
        ];
        let coinbase_tx = EngineTransaction {
            version: 1,
            transaction_inputs: coinbase_tx_inputs,
            transaction_outputs: coinbase_tx_outputs,
            locktime: 0,
        };
        let coinbase_bytes = coinbase_tx.serialize_no_witness();
        let coinbase_txid = double_sha256(@coinbase_bytes);
        let transaction = EngineTransaction {
            version: 1,
            transaction_inputs: array![
                EngineTransactionInput {
                    previous_outpoint: EngineOutPoint { txid: coinbase_txid, vout: 0, },
                    signature_script: script_sig,
                    witness: array![],
                    sequence: 0xffffffff,
                }
            ],
            transaction_outputs: array![
                EngineTransactionOutput { value: 0, publickey_script: "", }
            ],
            locktime: 0,
        };
        // let transaction = EngineTransaction {
        //     version: 1,
        //     transaction_inputs: array![
        //         EngineTransactionInput {
        //             previous_outpoint: EngineOutPoint { txid: 0x0, vout: 0, },
        //             signature_script: script_sig,
        //             witness: array![],
        //             sequence: 0xffffffff,
        //         }
        //     ],
        //     transaction_outputs: array![],
        //     locktime: 0,
        // };
        transaction
    }

    fn new_signed_witness(
        script_sig: ByteArray, pubkey_script: ByteArray, witness: Array<ByteArray>, value: i64
    ) -> EngineTransaction {
        let coinbase_tx_inputs = array![
            EngineTransactionInput {
                previous_outpoint: EngineOutPoint { txid: 0x0, vout: 0xffffffff, },
                signature_script: "\x00\x00",
                witness: array![],
                sequence: 0xffffffff,
            }
        ];
        let coinbase_tx_outputs = array![
            EngineTransactionOutput { value: value, publickey_script: pubkey_script, }
        ];
        let coinbase_tx = EngineTransaction {
            version: 1,
            transaction_inputs: coinbase_tx_inputs,
            transaction_outputs: coinbase_tx_outputs,
            locktime: 0,
        };
        let coinbase_bytes = coinbase_tx.serialize_no_witness();
        let coinbase_txid = double_sha256(@coinbase_bytes);
        let transaction = EngineTransaction {
            version: 1,
            transaction_inputs: array![
                EngineTransactionInput {
                    previous_outpoint: EngineOutPoint { txid: coinbase_txid, vout: 0, },
                    signature_script: script_sig,
                    witness: witness,
                    sequence: 0xffffffff,
                }
            ],
            transaction_outputs: array![
                EngineTransactionOutput { value: value, publickey_script: "", }
            ],
            locktime: 0,
        };
        transaction
    }

    // Deserialize a transaction from a byte array.
    fn btc_decode(raw: ByteArray, encoding: u32) -> EngineTransaction {
        let mut offset: usize = 0;
        let version: i32 = byte_array_value_at_le(@raw, ref offset, 4).try_into().unwrap();
        if encoding == WITNESS_ENCODING {
            // consume flags
            offset += 2;
        }
        let input_len = read_var_int(@raw, ref offset);
        // TODO: Error handling and bounds checks
        // TODO: Byte orderings
        let mut i = 0;
        let mut inputs: Array<EngineTransactionInput> = array![];
        while i != input_len {
            let tx_id = u256 {
                high: byte_array_value_at_be(@raw, ref offset, 16).try_into().unwrap(),
                low: byte_array_value_at_be(@raw, ref offset, 16).try_into().unwrap(),
            };
            let vout: u32 = byte_array_value_at_le(@raw, ref offset, 4).try_into().unwrap();
            let script_len = read_var_int(@raw, ref offset).try_into().unwrap();
            let script = sub_byte_array(@raw, ref offset, script_len);
            let sequence: u32 = byte_array_value_at_le(@raw, ref offset, 4).try_into().unwrap();
            let input = EngineTransactionInput {
                previous_outpoint: EngineOutPoint { txid: tx_id, vout: vout },
                signature_script: script,
                witness: array![],
                sequence: sequence,
            };
            inputs.append(input);
            i += 1;
        };

        let output_len = read_var_int(@raw, ref offset);
        let mut i = 0;
        let mut outputs: Array<EngineTransactionOutput> = array![];
        while i != output_len {
            // TODO: negative values
            let value: i64 = byte_array_value_at_le(@raw, ref offset, 8).try_into().unwrap();
            let script_len = read_var_int(@raw, ref offset).try_into().unwrap();
            let script = sub_byte_array(@raw, ref offset, script_len);
            let output = EngineTransactionOutput { value: value, publickey_script: script, };
            outputs.append(output);
            i += 1;
        };

        let mut inputs_with_witness: Array<EngineTransactionInput> = array![];

        if encoding == WITNESS_ENCODING {
            // one witness for each input
            i = 0;
            while i != input_len {
                let witness_count = read_var_int(@raw, ref offset);
                let mut j = 0;
                let mut witness: Array<ByteArray> = array![];
                while j != witness_count {
                    let script_len = read_var_int(@raw, ref offset).try_into().unwrap();
                    let script = sub_byte_array(@raw, ref offset, script_len);
                    witness.append(script);
                    j += 1;
                };
                // update Transaction Input
                let input = inputs.at(i.try_into().unwrap());
                let mut input_with_witness = input.clone();
                input_with_witness.witness = witness;
                inputs_with_witness.append(input_with_witness);
                i += 1;
            };
        }
        let locktime: u32 = byte_array_value_at_le(@raw, ref offset, 4).try_into().unwrap();

        if encoding == WITNESS_ENCODING {
            EngineTransaction {
                version: version,
                transaction_inputs: inputs_with_witness,
                transaction_outputs: outputs,
                locktime: locktime,
            }
        } else {
            EngineTransaction {
                version: version,
                transaction_inputs: inputs,
                transaction_outputs: outputs,
                locktime: locktime,
            }
        }
    }

    fn deserialize(raw: ByteArray) -> EngineTransaction {
        let mut offset: usize = 0;
        let _version: i32 = byte_array_value_at_le(@raw, ref offset, 4).try_into().unwrap();
        let flags: u16 = byte_array_value_at_le(@raw, ref offset, 2).try_into().unwrap();
        if flags == 0x100 {
            Self::btc_decode(raw, WITNESS_ENCODING)
        } else {
            Self::btc_decode(raw, BASE_ENCODING)
        }
    }

    fn deserialize_no_witness(raw: ByteArray) -> EngineTransaction {
        Self::btc_decode(raw, BASE_ENCODING)
    }

    // Serialize the transaction data for hashing based on encoding used.
    fn btc_encode(self: EngineTransaction, encoding: u32) -> ByteArray {
        let mut bytes = "";
        bytes.append_word_rev(self.version.into(), 4);
        // TODO: Witness encoding

        // Serialize each input in the transaction.
        let input_len: usize = self.transaction_inputs.len();
        write_var_int(ref bytes, input_len.into());
        let mut i: usize = 0;
        while i != input_len {
            let input: @EngineTransactionInput = self.transaction_inputs.at(i);
            let input_txid: u256 = *input.previous_outpoint.txid;
            let vout: u32 = *input.previous_outpoint.vout;
            let script: @ByteArray = input.signature_script;
            let script_len: usize = script.len();
            let sequence: u32 = *input.sequence;

            bytes.append_word(input_txid.high.into(), 16);
            bytes.append_word(input_txid.low.into(), 16);
            bytes.append_word_rev(vout.into(), 4);
            write_var_int(ref bytes, script_len.into());
            bytes.append(script);
            bytes.append_word_rev(sequence.into(), 4);

            i += 1;
        };

        // Serialize each output in the transaction.
        let output_len: usize = self.transaction_outputs.len();
        write_var_int(ref bytes, output_len.into());
        i = 0;
        while i != output_len {
            let output: @EngineTransactionOutput = self.transaction_outputs.at(i);
            let value: i64 = *output.value;
            let script: @ByteArray = output.publickey_script;
            let script_len: usize = script.len();

            bytes.append_word_rev(value.into(), 8);
            write_var_int(ref bytes, script_len.into());
            bytes.append(script);

            i += 1;
        };

        bytes.append_word_rev(self.locktime.into(), 4);
        bytes
    }

    fn serialize(self: EngineTransaction) -> ByteArray {
        self.btc_encode(WITNESS_ENCODING)
    }

    fn serialize_no_witness(self: EngineTransaction) -> ByteArray {
        self.btc_encode(BASE_ENCODING)
    }

    fn calculate_block_subsidy(block_height: u32) -> i64 {
        let halvings = block_height / 210000;
        shr::<i64, u32>(5000000000, halvings)
    }

    fn is_coinbase(self: @EngineTransaction) -> bool {
        if self.transaction_inputs.len() != 1 {
            return false;
        }

        let input = self.transaction_inputs.at(0);
        if input.previous_outpoint.txid != @0 || input.previous_outpoint.vout != @0xFFFFFFFF {
            return false;
        }

        true
    }

    fn validate_coinbase(
        self: EngineTransaction, block_height: u32, total_fees: i64
    ) -> Result<(), felt252> {
        if !self.is_coinbase() {
            return Result::Err(Error::INVALID_COINBASE);
        }

        let input = self.transaction_inputs.at(0);
        let script_len = input.signature_script.len();
        if script_len < 2 || script_len > 100 {
            return Result::Err(Error::INVALID_COINBASE);
        }

        let subsidy = Self::calculate_block_subsidy(block_height);
        let mut total_out: i64 = 0;
        let output_len = self.transaction_outputs.len();
        let mut i = 0;
        while i != output_len {
            let output = self.transaction_outputs.at(i);
            total_out += *output.value;
            i += 1;
        };
        if total_out > total_fees + subsidy {
            return Result::Err(Error::INVALID_COINBASE);
        }

        // TODO: BIP34 checks for block height?

        Result::Ok(())
    }

    fn print(self: @EngineTransaction) {
        println!("Version: {}", self.version);
        println!("Locktime: {}", self.locktime);
        println!("Inputs: {}", self.transaction_inputs.len());
        let mut i = 0;
        while i != self.transaction_inputs.len() {
            let input = self.transaction_inputs.at(i);
            println!(
                "  Input {}: {} {}", i, input.previous_outpoint.txid, input.previous_outpoint.vout
            );
            println!("    Txid: {}", input.previous_outpoint.txid);
            println!("    Vout: {}", input.previous_outpoint.vout);
            println!("    Script: {}", bytecode_to_hex(input.signature_script));
            println!("    Sequence: {}", input.sequence);
            println!("    Witness: {}", input.witness.len());
            let mut j = 0;
            while j != input.witness.len() {
                println!("      Witness {}: {}", j, bytecode_to_hex(input.witness.at(j)));
                j += 1;
            };
            i += 1;
        };
        println!("Outputs: {}", self.transaction_outputs.len());
        i = 0;
        while i != self.transaction_outputs.len() {
            let output = self.transaction_outputs.at(i);
            println!("  Output {}: {}", i, output.value);
            println!("    Script: {}", bytecode_to_hex(output.publickey_script));
            println!("    Value: {}", output.value);
            i += 1;
        };
    }
}

impl TransactionDefault of Default<EngineTransaction> {
    fn default() -> EngineTransaction {
        let default_txin = EngineTransactionInput {
            previous_outpoint: EngineOutPoint { txid: 0, vout: 0, },
            signature_script: "",
            witness: array![],
            sequence: 0xffffffff,
        };
        let transaction = EngineTransaction {
            version: 0,
            transaction_inputs: array![default_txin],
            transaction_outputs: array![],
            locktime: 0,
        };
        transaction
    }
}

pub trait EngineTransactionInputTrait<I> {
    fn get_prevout_txid(self: @I) -> u256;
    fn get_prevout_vout(self: @I) -> u32;
    fn get_signature_script(self: @I) -> @ByteArray;
    fn get_witness(self: @I) -> Span<ByteArray>;
    fn get_sequence(self: @I) -> u32;
}

pub impl EngineTransactionInputTraitInternalImpl of EngineTransactionInputTrait<
    EngineTransactionInput
> {
    fn get_prevout_txid(self: @EngineTransactionInput) -> u256 {
        *self.previous_outpoint.txid
    }

    fn get_prevout_vout(self: @EngineTransactionInput) -> u32 {
        *self.previous_outpoint.vout
    }

    fn get_signature_script(self: @EngineTransactionInput) -> @ByteArray {
        self.signature_script
    }

    fn get_witness(self: @EngineTransactionInput) -> Span<ByteArray> {
        self.witness.span()
    }

    fn get_sequence(self: @EngineTransactionInput) -> u32 {
        *self.sequence
    }
}

pub trait EngineTransactionOutputTrait<O> {
    fn get_publickey_script(self: @O) -> @ByteArray;
    fn get_value(self: @O) -> i64;
}

pub impl EngineTransactionOutputTraitInternalImpl of EngineTransactionOutputTrait<
    EngineTransactionOutput
> {
    fn get_publickey_script(self: @EngineTransactionOutput) -> @ByteArray {
        self.publickey_script
    }

    fn get_value(self: @EngineTransactionOutput) -> i64 {
        *self.value
    }
}

pub trait EngineTransactionTrait<
    T, I, O, +EngineTransactionInputTrait<I>, +EngineTransactionOutputTrait<O>
> {
    fn get_version(self: @T) -> i32;
    fn get_transaction_inputs(self: @T) -> Span<I>;
    fn get_transaction_outputs(self: @T) -> Span<O>;
    fn get_locktime(self: @T) -> u32;
}

pub impl EngineTransactionTraitInternalImpl of EngineTransactionTrait<
    EngineTransaction,
    EngineTransactionInput,
    EngineTransactionOutput,
    EngineTransactionInputTraitInternalImpl,
    EngineTransactionOutputTraitInternalImpl
> {
    fn get_version(self: @EngineTransaction) -> i32 {
        *self.version
    }

    fn get_transaction_inputs(self: @EngineTransaction) -> Span<EngineTransactionInput> {
        self.transaction_inputs.span()
    }

    fn get_transaction_outputs(self: @EngineTransaction) -> Span<EngineTransactionOutput> {
        self.transaction_outputs.span()
    }

    fn get_locktime(self: @EngineTransaction) -> u32 {
        *self.locktime
    }
}

// hash_cache.cairo

#[derive(Clone, Copy, Drop)]
pub struct SegwitSigHashMidstate {
    pub hash_prevouts_v0: u256,
    pub hash_sequence_v0: u256,
    pub hash_outputs_v0: u256
}

pub trait SigHashMidstateTrait<
    I,
    O,
    T,
    +EngineTransactionInputTrait<I>,
    +EngineTransactionOutputTrait<O>,
    +EngineTransactionTrait<T, I, O>
> {
    fn new(transaction: @T) -> SegwitSigHashMidstate;
}

pub impl SigHashMidstateImpl<
    I,
    O,
    T,
    impl IEngineTransactionInput: EngineTransactionInputTrait<I>,
    impl IEngineTransactionOutput: EngineTransactionOutputTrait<O>,
    impl IEngineTransaction: EngineTransactionTrait<
        T, I, O, IEngineTransactionInput, IEngineTransactionOutput
    >
> of SigHashMidstateTrait<I, O, T> {
    fn new(transaction: @T) -> SegwitSigHashMidstate {
        let mut prevouts_v0_bytes: ByteArray = "";
        let inputs = transaction.get_transaction_inputs();
        for input in inputs {
            let txid = input.get_prevout_txid();
            prevouts_v0_bytes.append_word(txid.high.into(), 16);
            prevouts_v0_bytes.append_word(txid.low.into(), 16);
            prevouts_v0_bytes.append_word_rev(input.get_prevout_vout().into(), 4);
        };
        let mut sequence_v0_bytes: ByteArray = "";
        for input in inputs {
            sequence_v0_bytes.append_word_rev(input.get_sequence().into(), 4);
        };
        let mut outputs_v0_bytes: ByteArray = "";
        let outputs = transaction.get_transaction_outputs();
        for output in outputs {
            outputs_v0_bytes.append_word_rev(output.get_value().into(), 8);
            write_var_int(ref outputs_v0_bytes, output.get_publickey_script().len().into());
            outputs_v0_bytes.append(output.get_publickey_script());
        };
        SegwitSigHashMidstate {
            hash_prevouts_v0: double_sha256(@prevouts_v0_bytes),
            hash_sequence_v0: double_sha256(@sequence_v0_bytes),
            hash_outputs_v0: double_sha256(@outputs_v0_bytes)
        }
    }
}

// SigCache implements an Schnorr+ECDSA signature verification cache. Only valid signatures will be
// added to the cache.
pub trait SigCacheTrait<S> {
    // Returns true if sig cache contains sig_hash corresponding to signature and public key
    fn exists(sig_hash: u256, signature: ByteArray, pub_key: ByteArray) -> bool;
    // Adds a signature to the cache
    fn add(sig_hash: u256, signature: ByteArray, pub_key: ByteArray);
}

// TODO
#[derive(Drop)]
pub struct HashCache<T> {}

// HashCache caches the midstate of segwit v0 and v1 sighashes
pub trait HashCacheTrait<
    I,
    O,
    T,
    +EngineTransactionInputTrait<I>,
    +EngineTransactionOutputTrait<O>,
    +EngineTransactionTrait<T, I, O>
> {
    fn new(transaction: @T) -> HashCache<T>;

    // v0 represents sighash midstate used in the base segwit signatures BIP-143
    fn get_hash_prevouts_v0(self: @HashCache<T>) -> u256;
    fn get_hash_sequence_v0(self: @HashCache<T>) -> u256;
    fn get_hash_outputs_v0(self: @HashCache<T>) -> u256;

    // v1 represents sighash midstate used to compute taproot signatures BIP-341
    fn get_hash_prevouts_v1(self: @HashCache<T>) -> u256;
    fn get_hash_sequence_v1(self: @HashCache<T>) -> u256;
    fn get_hash_outputs_v1(self: @HashCache<T>) -> u256;
    fn get_hash_input_scripts_v1(self: @HashCache<T>) -> u256;
}


pub impl HashCacheImpl<
    I,
    O,
    T,
    impl IEngineTransactionInput: EngineTransactionInputTrait<I>,
    impl IEngineTransactionOutput: EngineTransactionOutputTrait<O>,
    impl IEngineTransaction: EngineTransactionTrait<
        T, I, O, IEngineTransactionInput, IEngineTransactionOutput
    >
> of HashCacheTrait<I, O, T> {
    fn new(transaction: @T) -> HashCache<T> {
        HashCache {}
    }

    fn get_hash_prevouts_v0(self: @HashCache<T>) -> u256 {
        0
    }

    fn get_hash_sequence_v0(self: @HashCache<T>) -> u256 {
        0
    }

    fn get_hash_outputs_v0(self: @HashCache<T>) -> u256 {
        0
    }

    fn get_hash_prevouts_v1(self: @HashCache<T>) -> u256 {
        0
    }

    fn get_hash_sequence_v1(self: @HashCache<T>) -> u256 {
        0
    }

    fn get_hash_outputs_v1(self: @HashCache<T>) -> u256 {
        0
    }

    fn get_hash_input_scripts_v1(self: @HashCache<T>) -> u256 {
        0
    }
}

// witness.cairo

fn byte_to_smallint(byte: u8) -> Result<i64, felt252> {
    if byte == Opcode::OP_0 {
        return Result::Ok(0);
    }
    if byte >= Opcode::OP_1 && byte <= Opcode::OP_16 {
        return Result::Ok((byte - Opcode::OP_1 + 1).into());
    }
    Result::Err('Invalid small int')
}

pub fn parse_witness_program(witness: @ByteArray) -> Result<(i64, ByteArray), felt252> {
    if witness.len() < 4 || witness.len() > 42 {
        return Result::Err('Invalid witness program length');
    }

    let version: i64 = byte_to_smallint(witness[0])?;
    let data_len = data_len(witness, 1)?;
    let program: ByteArray = data_at(witness, 2, data_len)?;
    if !Opcode::is_canonical_push(witness[1], @program) {
        return Result::Err('Non-canonical witness program');
    }

    return Result::Ok((version, program));
}

pub fn is_witness_program(program: @ByteArray) -> bool {
    return parse_witness_program(program).is_ok();
}

pub fn parse_witness_input(input: ByteArray) -> Array<ByteArray> {
    // Comma seperated list of witness data as hex strings
    let mut witness_data: Array<ByteArray> = array![];
    let mut i = 0;
    let mut temp_witness: ByteArray = "";
    let witness_input_len = input.len();
    while i != witness_input_len {
        let char = input[i].into();
        if char == ',' {
            let witness_bytes = hex_to_bytecode(@temp_witness);
            witness_data.append(witness_bytes);
            temp_witness = "";
        } else {
            temp_witness.append_byte(char);
        }
        i += 1;
    };
    // Handle the last witness data
    let witness_bytes = hex_to_bytecode(@temp_witness);
    witness_data.append(witness_bytes);

    // TODO: Empty witness?

    witness_data
}

// engine.cairo

pub const MAX_STACK_SIZE: u32 = 1000;
pub const MAX_SCRIPT_SIZE: u32 = 10000;
pub const MAX_OPS_PER_SCRIPT: u32 = 201;
pub const MAX_SCRIPT_ELEMENT_SIZE: u32 = 520;

// Represents the VM that executes Bitcoin scripts
#[derive(Destruct)]
pub struct Engine<T> {
    // Execution behaviour flags
    flags: u32,
    // Is Bip16 p2sh
    bip16: bool,
    // Transaction context being executed
    pub transaction: @T,
    // Input index within the tx containing signature script being executed
    pub tx_idx: u32,
    // Amount of the input being spent
    pub amount: i64,
    // The script to execute
    scripts: Array<@ByteArray>,
    // Index of the current script being executed
    script_idx: usize,
    // Program counter within the current script
    pub opcode_idx: usize,
    // The witness program
    pub witness_program: ByteArray,
    // The witness version
    pub witness_version: i64,
    // Primary data stack
    pub dstack: ScriptStack,
    // Alternate data stack
    pub astack: ScriptStack,
    // Tracks conditonal execution state supporting nested conditionals
    pub cond_stack: ConditionalStack,
    // Copy of the stack from 1st script in a P2SH exec
    pub saved_first_stack: Span<ByteArray>,
    // Position within script of last OP_CODESEPARATOR
    pub last_code_sep: u32,
    // Count number of non-push opcodes
    pub num_ops: u32,
}

// TODO: SigCache
pub trait EngineTrait<
    I,
    O,
    T,
    +EngineTransactionInputTrait<I>,
    +EngineTransactionOutputTrait<O>,
    +EngineTransactionTrait<T, I, O>,
    +HashCacheTrait<I, O, T>
> {
    // Create a new Engine with the given script
    fn new(
        script_pubkey: @ByteArray,
        transaction: @T,
        tx_idx: u32,
        flags: u32,
        amount: i64,
        hash_cache: @HashCache<T>
    ) -> Result<Engine<T>, felt252>;
    // Executes a single step of the script, returning true if more steps are needed
    fn step(ref self: Engine<T>) -> Result<bool, felt252>;
    // Executes the entire script and returns top of stack or error if script fails
    fn execute(ref self: Engine<T>) -> Result<ByteArray, felt252>;
}

pub impl EngineImpl<
    I,
    O,
    T,
    impl IEngineTransactionInput: EngineTransactionInputTrait<I>,
    impl IEngineTransactionOutput: EngineTransactionOutputTrait<O>,
    impl IEngineTransaction: EngineTransactionTrait<
        T, I, O, IEngineTransactionInput, IEngineTransactionOutput
    >,
    +Drop<I>,
    +Drop<O>,
    +Drop<T>,
> of EngineTrait<I, O, T> {
    // Create a new Engine with the given script
    fn new(
        script_pubkey: @ByteArray,
        transaction: @T,
        tx_idx: u32,
        flags: u32,
        amount: i64,
        hash_cache: @HashCache<T>
    ) -> Result<Engine<T>, felt252> {
        let transaction_inputs = transaction.get_transaction_inputs();
        if tx_idx >= transaction_inputs.len() {
            return Result::Err('Engine::new: tx_idx invalid');
        }
        let tx_input = transaction_inputs[tx_idx];
        let script_sig = tx_input.get_signature_script();

        if script_sig.len() == 0 && script_pubkey.len() == 0 {
            return Result::Err(Error::SCRIPT_EMPTY_STACK);
        }

        let witness_len = tx_input.get_witness().len();
        let mut engine = Engine {
            flags: flags,
            bip16: false,
            transaction: transaction,
            tx_idx: tx_idx,
            amount: amount,
            scripts: array![script_sig, script_pubkey],
            script_idx: 0,
            opcode_idx: 0,
            witness_program: "",
            witness_version: 0,
            dstack: ScriptStackImpl::new(),
            astack: ScriptStackImpl::new(),
            cond_stack: ConditionalStackImpl::new(),
            saved_first_stack: array![].span(),
            last_code_sep: 0,
            num_ops: 0,
        };

        if engine.has_flag(ScriptFlags::ScriptVerifyCleanStack)
            && (!engine.has_flag(ScriptFlags::ScriptBip16)
                && !engine.has_flag(ScriptFlags::ScriptVerifyWitness)) {
            return Result::Err('Engine::new: invalid flag combo');
        }

        if engine.has_flag(ScriptFlags::ScriptVerifySigPushOnly)
            && !is_push_only(script_sig) {
            return Result::Err('Engine::new: not pushonly');
        }

        let mut bip16 = false;
        if engine.has_flag(ScriptFlags::ScriptBip16) && is_script_hash(script_pubkey) {
            if !engine.has_flag(ScriptFlags::ScriptVerifySigPushOnly)
                && !is_push_only(script_sig) {
                return Result::Err('Engine::new: p2sh not pushonly');
            }
            engine.bip16 = true;
            bip16 = true;
        }

        let mut i = 0;
        let mut valid_sizes = true;
        let scripts_len = engine.scripts.len();
        while i != scripts_len {
            let script = *(engine.scripts[i]);
            if script.len() > MAX_SCRIPT_SIZE {
                valid_sizes = false;
                break;
            }
            // TODO: Check parses?
            i += 1;
        };
        if !valid_sizes {
            return Result::Err('Engine::new: script too large');
        }

        if script_sig.len() == 0 {
            engine.script_idx = 1;
        }

        if engine.has_flag(ScriptFlags::ScriptVerifyMinimalData) {
            engine.dstack.verify_minimal_data = true;
            engine.astack.verify_minimal_data = true;
        }

        if engine.has_flag(ScriptFlags::ScriptVerifyWitness) {
            if !engine.has_flag(ScriptFlags::ScriptBip16) {
                return Result::Err('Engine::new: witness in nonp2sh');
            }

            let mut witness_program: ByteArray = "";
            if is_witness_program(script_pubkey) {
                if script_sig.len() != 0 {
                    return Result::Err(Error::WITNESS_MALLEATED);
                }
                witness_program = script_pubkey.clone();
            } else if witness_len != 0 && bip16 {
                let sig_clone = script_sig.clone();
                if sig_clone.len() > 2 {
                    let first_elem = sig_clone[0];
                    let mut remaining = "";
                    let mut i = 1;
                    // TODO: Optimize
                    let sig_len = sig_clone.len();
                    while i != sig_len {
                        remaining.append_byte(sig_clone[i]);
                        i += 1;
                    };
                    if Opcode::is_canonical_push(first_elem, @remaining)
                        && is_witness_program(@remaining) {
                        witness_program = remaining;
                    } else {
                        return Result::Err(Error::WITNESS_MALLEATED_P2SH);
                    }
                } else {
                    return Result::Err(Error::WITNESS_MALLEATED_P2SH);
                }
            }

            if witness_program.len() != 0 {
                let (witness_version, witness_program) = parse_witness_program(
                    @witness_program
                )?;
                engine.witness_version = witness_version;
                engine.witness_program = witness_program;
            } else if engine.witness_program.len() == 0 && witness_len != 0 {
                return Result::Err(Error::WITNESS_UNEXPECTED);
            }
        }

        return Result::Ok(engine);
    }

    fn step(ref self: Engine<T>) -> Result<bool, felt252> {
        // TODO: Make it match engine.execute after recent changes
        if self.script_idx >= self.scripts.len() {
            return Result::Ok(false);
        }
        let script = *(self.scripts[self.script_idx]);
        if self.opcode_idx >= script.len() {
            // Empty script skip
            if self.cond_stack.len() > 0 {
                return Result::Err(Error::SCRIPT_UNBALANCED_CONDITIONAL_STACK);
            }
            self.astack = ScriptStackImpl::new();
            if self.dstack.verify_minimal_data {
                self.astack.verify_minimal_data = true;
            }
            self.opcode_idx = 0;
            self.last_code_sep = 0;
            self.script_idx += 1;
            return self.step();
        }
        let opcode = script[self.opcode_idx];

        let illegal_opcode = Opcode::is_opcode_always_illegal(opcode, ref self);
        if illegal_opcode.is_err() {
            return Result::Err(illegal_opcode.unwrap_err());
        }

        if !self.cond_stack.branch_executing() && !Opcode::is_branching_opcode(opcode) {
            self.skip()?;
            return Result::Ok(true);
        }

        if self.dstack.verify_minimal_data
            && self.cond_stack.branch_executing()
            && opcode >= 0
            && opcode <= Opcode::OP_PUSHDATA4 {
            self.check_minimal_data_push(opcode)?;
        }

        let res = Opcode::execute(opcode, ref self);
        if res.is_err() {
            return Result::Err(res.unwrap_err());
        }
        self.check_stack_size()?;
        self.opcode_idx += 1;
        if self.opcode_idx >= script.len() {
            if self.cond_stack.len() > 0 {
                return Result::Err(Error::SCRIPT_UNBALANCED_CONDITIONAL_STACK);
            }
            self.astack = ScriptStackImpl::new();
            if self.dstack.verify_minimal_data {
                self.astack.verify_minimal_data = true;
            }
            self.opcode_idx = 0;
            self.last_code_sep = 0;
            self.script_idx += 1;
        }
        return Result::Ok(true);
    }

    // Executes the entire script and returns top of stack or error if script fails
    fn execute(ref self: Engine<T>) -> Result<ByteArray, felt252> {
        let mut err = '';
        // TODO: Optimize with != instead of < and check for bounds errors within the loop
        while self.script_idx < self.scripts.len() {
            let script: @ByteArray = *self.scripts[self.script_idx];
            let script_len = script.len();
            if script_len == 0 {
                self.script_idx += 1;
                continue;
            }
            while self.opcode_idx < script_len {
                let opcode_idx = self.opcode_idx;
                let opcode = script[opcode_idx];

                // TODO: Can this be defered to opcode execution like disabled
                // Check if the opcode is always illegal (reserved).
                let illegal_opcode = Opcode::is_opcode_always_illegal(opcode, ref self);
                if illegal_opcode.is_err() {
                    err = illegal_opcode.unwrap_err();
                    break;
                }

                if opcode > Opcode::OP_16 {
                    self.num_ops += 1;
                    if self.num_ops > MAX_OPS_PER_SCRIPT {
                        err = Error::SCRIPT_TOO_MANY_OPERATIONS;
                        break;
                    }
                } else if Opcode::is_push_opcode(opcode) {
                    let res = push_data_len(script, opcode_idx);
                    if res.is_err() {
                        err = res.unwrap_err();
                        break;
                    }
                    if res.unwrap() > MAX_SCRIPT_ELEMENT_SIZE {
                        err = Error::SCRIPT_PUSH_SIZE;
                        break;
                    }
                }

                if !self.cond_stack.branch_executing() && !Opcode::is_branching_opcode(opcode) {
                    let res = self.skip();
                    if res.is_err() {
                        err = res.unwrap_err();
                        break;
                    }
                    continue;
                }

                if self.dstack.verify_minimal_data
                    && self.cond_stack.branch_executing()
                    && opcode >= 0
                    && opcode <= Opcode::OP_PUSHDATA4 {
                    let res = self.check_minimal_data_push(opcode);
                    if res.is_err() {
                        err = res.unwrap_err();
                        break;
                    }
                }

                let res = Opcode::execute(opcode, ref self);
                if res.is_err() {
                    err = res.unwrap_err();
                    break;
                }
                let res = self.check_stack_size();
                if res.is_err() {
                    err = res.unwrap_err();
                    break;
                }
                self.opcode_idx += 1;
            };
            if err != '' {
                break;
            }
            if self.cond_stack.len() != 0 {
                err = Error::SCRIPT_UNBALANCED_CONDITIONAL_STACK;
                break;
            }
            self.astack = ScriptStackImpl::new();
            if self.dstack.verify_minimal_data {
                self.astack.verify_minimal_data = true;
            }
            self.num_ops = 0;
            self.opcode_idx = 0;
            if self.script_idx == 0 && self.bip16 {
                self.script_idx += 1;
                // TODO: Use @ instead of clone span
                self.saved_first_stack = self.dstack.stack_to_span();
            } else if self.script_idx == 1 && self.bip16 {
                self.script_idx += 1;

                let res = self.check_error_condition(false);
                if res.is_err() {
                    err = res.unwrap_err();
                    break;
                }
                let saved_stack_len = self.saved_first_stack.len();
                let redeem_script = self.saved_first_stack[saved_stack_len - 1];
                // TODO: check script parses?
                self.scripts.append(redeem_script);
                self.dstack.set_stack(self.saved_first_stack, 0, saved_stack_len - 1);
            } else if (self.script_idx == 1 && self.witness_program.len() != 0)
                || (self.script_idx == 2 && self.witness_program.len() != 0 && self.bip16) {
                self.script_idx += 1;
                let tx_input = self.transaction.get_transaction_inputs()[self.tx_idx];
                let witness = tx_input.get_witness();
                let res = self.verify_witness(witness);
                if res.is_err() {
                    err = res.unwrap_err();
                    break;
                }
            } else {
                self.script_idx += 1;
            }
            self.last_code_sep = 0;
            // TODO: other things
        };
        if err != '' {
            return Result::Err(err);
        }

        return self.check_error_condition(true);
    }
}

// TODO: Remove functions that can be locally used only
pub trait EngineInternalTrait<
    I,
    O,
    T,
    +EngineTransactionInputTrait<I>,
    +EngineTransactionOutputTrait<O>,
    +EngineTransactionTrait<T, I, O>,
    +HashCacheTrait<I, O, T>,
> {
    // Pulls the next len bytes from the script and advances the program counter
    fn pull_data(ref self: Engine<T>, len: usize) -> Result<ByteArray, felt252>;
    // Return true if the script engine instance has the specified flag set.
    fn has_flag(ref self: Engine<T>, flag: ScriptFlags) -> bool;
    // Pop bool enforcing minimal if
    fn pop_if_bool(ref self: Engine<T>) -> Result<bool, felt252>;
    // Return true if the witness program was active
    fn is_witness_active(ref self: Engine<T>, version: i64) -> bool;
    // Return the script since last OP_CODESEPARATOR
    fn sub_script(ref self: Engine<T>) -> ByteArray;
    // Returns the data stack
    fn get_dstack(ref self: Engine<T>) -> Span<ByteArray>;
    // Returns the alt stack
    fn get_astack(ref self: Engine<T>) -> Span<ByteArray>;
    // Skips the next opcode in execution based on execution rules
    fn skip(ref self: Engine<T>) -> Result<(), felt252>;
    // Ensure the stack size is within limits
    fn check_stack_size(ref self: Engine<T>) -> Result<(), felt252>;
    // Check if the next opcode is a minimal push
    fn check_minimal_data_push(ref self: Engine<T>, opcode: u8) -> Result<(), felt252>;
    // Validate witness program using witness input
    fn verify_witness(ref self: Engine<T>, witness: Span<ByteArray>) -> Result<(), felt252>;
    // Check if the script has failed and return an error if it has
    fn check_error_condition(ref self: Engine<T>, final: bool) -> Result<ByteArray, felt252>;
    // Prints the engine state as json
    fn json(ref self: Engine<T>);
}

pub impl EngineInternalImpl<
    I,
    O,
    T,
    impl IEngineTransactionInput: EngineTransactionInputTrait<I>,
    impl IEngineTransactionOutput: EngineTransactionOutputTrait<O>,
    impl IEngineTransaction: EngineTransactionTrait<
        T, I, O, IEngineTransactionInput, IEngineTransactionOutput
    >,
    +Drop<T>,
> of EngineInternalTrait<I, O, T> {
    fn pull_data(ref self: Engine<T>, len: usize) -> Result<ByteArray, felt252> {
        let script = *(self.scripts[self.script_idx]);
        let data = data_at(script, self.opcode_idx + 1, len)?;
        self.opcode_idx += len;
        return Result::Ok(data);
    }

    fn has_flag(ref self: Engine<T>, flag: ScriptFlags) -> bool {
        self.flags & flag.into() == flag.into()
    }

    fn pop_if_bool(ref self: Engine<T>) -> Result<bool, felt252> {
        if !self.is_witness_active(0) || !self.has_flag(ScriptFlags::ScriptVerifyMinimalIf) {
            return self.dstack.pop_bool();
        }
        let top = self.dstack.pop_byte_array()?;
        if top.len() > 1 {
            return Result::Err(Error::MINIMAL_IF);
        }

        if top.len() == 1 && top[0] != 0x01 {
            return Result::Err(Error::MINIMAL_IF);
        }
        return Result::Ok(byte_array_to_bool(@top));
    }

    fn is_witness_active(ref self: Engine<T>, version: i64) -> bool {
        return self.witness_version == version && self.witness_program.len() != 0;
    }

    fn sub_script(ref self: Engine<T>) -> ByteArray {
        let script = *(self.scripts[self.script_idx]);
        if self.last_code_sep == 0 {
            return script.clone();
        }

        let mut sub_script = "";
        let mut i = self.last_code_sep;
        let script_len = script.len();
        while i != script_len {
            sub_script.append_byte(script[i]);
            i += 1;
        };
        return sub_script;
    }

    fn get_dstack(ref self: Engine<T>) -> Span<ByteArray> {
        return self.dstack.stack_to_span();
    }

    fn get_astack(ref self: Engine<T>) -> Span<ByteArray> {
        return self.astack.stack_to_span();
    }

    fn skip(ref self: Engine<T>) -> Result<(), felt252> {
        let script = *(self.scripts[self.script_idx]);
        let opcode = script.at(self.opcode_idx).unwrap();
        Opcode::is_opcode_disabled(opcode, ref self)?;
        let next = next(script, self.opcode_idx)?;
        self.opcode_idx = next;
        return Result::Ok(());
    }

    fn check_minimal_data_push(ref self: Engine<T>, opcode: u8) -> Result<(), felt252> {
        if opcode == Opcode::OP_0 {
            return Result::Ok(());
        }
        let script = *(self.scripts[self.script_idx]);
        if opcode == Opcode::OP_DATA_1 {
            let value: u8 = script.at(self.opcode_idx + 1).unwrap();
            if value >= 1 && value <= 16 {
                // Should be OP_1 to OP_16
                return Result::Err(Error::MINIMAL_DATA);
            }
            if value == 0x81 {
                // Should be OP_1NEGATE
                return Result::Err(Error::MINIMAL_DATA);
            }
        }

        // TODO: More checks?
        if !Opcode::is_push_opcode(opcode) {
            return Result::Ok(());
        }

        let len = push_data_len(script, self.opcode_idx)?;
        if len <= 75 {
            // Should have used OP_DATA_X
            return Result::Err(Error::MINIMAL_DATA);
        } else if len <= 255 && opcode != Opcode::OP_PUSHDATA1 {
            // Should have used OP_PUSHDATA1
            return Result::Err(Error::MINIMAL_DATA);
        } else if len <= 65535 && opcode != Opcode::OP_PUSHDATA2 {
            // Should have used OP_PUSHDATA2
            return Result::Err(Error::MINIMAL_DATA);
        }
        return Result::Ok(());
    }

    fn check_stack_size(ref self: Engine<T>) -> Result<(), felt252> {
        if self.dstack.len() + self.astack.len() > MAX_STACK_SIZE {
            return Result::Err(Error::STACK_OVERFLOW);
        }
        return Result::Ok(());
    }

    fn verify_witness(ref self: Engine<T>, witness: Span<ByteArray>) -> Result<(), felt252> {
        if self.is_witness_active(0) {
            // Verify a base witness (segwit) program, ie P2WSH || P2WPKH
            if self.witness_program.len() == 20 {
                // P2WPKH
                if witness.len() != 2 {
                    return Result::Err(Error::WITNESS_PROGRAM_MISMATCH);
                }
                // OP_DUP OP_HASH160 OP_DATA_20 <pkhash> OP_EQUALVERIFY OP_CHECKSIG
                let mut pk_script = hex_to_bytecode(@"0x76a914");
                pk_script.append(@self.witness_program);
                pk_script.append(@hex_to_bytecode(@"0x88ac"));

                self.scripts.append(@pk_script);
                self.dstack.set_stack(witness, 0, witness.len());
            } else if self.witness_program.len() == 32 {
                // P2WSH
                if witness.len() == 0 {
                    return Result::Err(Error::WITNESS_PROGRAM_EMPTY);
                }
                let witness_script = witness[witness.len() - 1];
                if witness_script.len() > MAX_SCRIPT_SIZE {
                    return Result::Err(Error::SCRIPT_TOO_LARGE);
                }
                let witness_hash = sha256_byte_array(witness_script);
                if witness_hash != self.witness_program {
                    return Result::Err(Error::WITNESS_PROGRAM_MISMATCH);
                }

                self.scripts.append(witness_script);
                self.dstack.set_stack(witness, 0, witness.len() - 1);
            } else {
                return Result::Err(Error::WITNESS_PROGRAM_WRONG_LENGTH);
            }
            // Sanity checks
            let mut err = '';
            for w in self
                .dstack
                .stack_to_span() {
                    if w.len() > MAX_SCRIPT_ELEMENT_SIZE {
                        err = Error::SCRIPT_PUSH_SIZE;
                        break;
                    }
                };
            if err != '' {
                return Result::Err(err);
            }
        } else if self.is_witness_active(1) {
            // Verify a taproot witness program
            // TODO: Implement
            return Result::Err('Taproot not implemented');
        } else if self.has_flag(ScriptFlags::ScriptVerifyDiscourageUpgradeableWitnessProgram) {
            return Result::Err(Error::DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM);
        } else {
            self.witness_program = "";
        }

        return Result::Ok(());
    }

    fn check_error_condition(ref self: Engine<T>, final: bool) -> Result<ByteArray, felt252> {
        // Check if execution is actually done
        if self.script_idx < self.scripts.len() {
            return Result::Err(Error::SCRIPT_UNFINISHED);
        }

        // Check if witness stack is clean
        if final && self.is_witness_active(0) && self.dstack.len() != 1 { // TODO: Hardcoded 0
            return Result::Err(Error::SCRIPT_NON_CLEAN_STACK);
        }
        if final && self.has_flag(ScriptFlags::ScriptVerifyCleanStack) && self.dstack.len() != 1 {
            return Result::Err(Error::SCRIPT_NON_CLEAN_STACK);
        }

        // Check if stack has at least one item
        if self.dstack.len() == 0 {
            return Result::Err(Error::SCRIPT_EMPTY_STACK);
        } else {
            // Check the final stack value
            let is_ok = self.dstack.peek_bool(0)?;
            if is_ok {
                return Result::Ok(self.dstack.peek_byte_array(0)?);
            } else {
                return Result::Err(Error::SCRIPT_FAILED);
            }
        }
    }

    fn json(ref self: Engine<T>) {
        self.dstack.json();
    }
}

// constants.cairo

pub fn opcode_false<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    engine.dstack.push_byte_array("");
    return Result::Ok(());
}

pub fn opcode_push_data<
    T,
    +Drop<T>,
    I,
    +Drop<I>,
    impl IEngineTransactionInputTrait: EngineTransactionInputTrait<I>,
    O,
    +Drop<O>,
    impl IEngineTransactionOutputTrait: EngineTransactionOutputTrait<O>,
    impl IEngineTransactionTrait: EngineTransactionTrait<
        T, I, O, IEngineTransactionInputTrait, IEngineTransactionOutputTrait
    >
>(
    n: usize, ref engine: Engine<T>
) -> Result<(), felt252> {
    let data = EngineInternalTrait::<I, O, T>::pull_data(ref engine, n)?;
    engine.dstack.push_byte_array(data);
    return Result::Ok(());
}

pub fn opcode_push_data_x<
    T,
    +Drop<T>,
    I,
    +Drop<I>,
    impl IEngineTransactionInputTrait: EngineTransactionInputTrait<I>,
    O,
    +Drop<O>,
    impl IEngineTransactionOutputTrait: EngineTransactionOutputTrait<O>,
    impl IEngineTransactionTrait: EngineTransactionTrait<
        T, I, O, IEngineTransactionInputTrait, IEngineTransactionOutputTrait
    >
>(
    n: usize, ref engine: Engine<T>
) -> Result<(), felt252> {
    let data_len_bytes = EngineInternalTrait::<I, O, T>::pull_data(ref engine, n)?;
    let data_len: usize = byte_array_to_felt252_le(@data_len_bytes).try_into().unwrap();
    let data = engine.pull_data(data_len)?;
    engine.dstack.push_byte_array(data);
    return Result::Ok(());
}

pub fn opcode_n<T, +Drop<T>>(n: i64, ref engine: Engine<T>) -> Result<(), felt252> {
    engine.dstack.push_int(n);
    return Result::Ok(());
}

pub fn opcode_1negate<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    engine.dstack.push_int(-1);
    return Result::Ok(());
}

// utils.cairo

pub fn abstract_verify<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let verified = engine.dstack.pop_bool()?;
    if !verified {
        return Result::Err(Error::VERIFY_FAILED);
    }
    Result::Ok(())
}

pub fn not_implemented<T>(ref engine: Engine<T>) -> Result<(), felt252> {
    return Result::Err(Error::OPCODE_RESERVED);
}

pub fn opcode_reserved<T>(msg: ByteArray, ref engine: Engine<T>) -> Result<(), felt252> {
    return Result::Err(Error::OPCODE_RESERVED);
}

pub fn opcode_disabled<T>(ref engine: Engine<T>) -> Result<(), felt252> {
    return Result::Err(Error::OPCODE_DISABLED);
}


// flow.cairo

pub fn opcode_nop<
    T,
    +Drop<T>,
    I,
    +Drop<I>,
    impl IEngineTransactionInputTrait: EngineTransactionInputTrait<I>,
    O,
    +Drop<O>,
    impl IEngineTransactionOutputTrait: EngineTransactionOutputTrait<O>,
    impl IEngineTransactionTrait: EngineTransactionTrait<
        T, I, O, IEngineTransactionInputTrait, IEngineTransactionOutputTrait
    >
>(
    ref engine: Engine<T>, opcode: u8
) -> Result<(), felt252> {
    if opcode != Opcode::OP_NOP
        && EngineInternalTrait::<
            I, O, T
        >::has_flag(ref engine, ScriptFlags::ScriptDiscourageUpgradableNops) {
        return Result::Err(Error::SCRIPT_DISCOURAGE_UPGRADABLE_NOPS);
    }
    return Result::Ok(());
}

// TODO: MOve to cond_stack
const op_cond_false: u8 = 0;
const op_cond_true: u8 = 1;
const op_cond_skip: u8 = 2;
pub fn opcode_if<
    T,
    +Drop<T>,
    I,
    +Drop<I>,
    impl IEngineTransactionInputTrait: EngineTransactionInputTrait<I>,
    O,
    +Drop<O>,
    impl IEngineTransactionOutputTrait: EngineTransactionOutputTrait<O>,
    impl IEngineTransactionTrait: EngineTransactionTrait<
        T, I, O, IEngineTransactionInputTrait, IEngineTransactionOutputTrait
    >
>(
    ref engine: Engine<T>
) -> Result<(), felt252> {
    let mut cond = op_cond_false;
    // TODO: Pop if bool
    if engine.cond_stack.branch_executing() {
        let ok = engine.pop_if_bool()?;
        if ok {
            cond = op_cond_true;
        }
    } else {
        cond = op_cond_skip;
    }
    engine.cond_stack.push(cond);
    return Result::Ok(());
}

pub fn opcode_notif<
    T,
    +Drop<T>,
    I,
    +Drop<I>,
    impl IEngineTransactionInputTrait: EngineTransactionInputTrait<I>,
    O,
    +Drop<O>,
    impl IEngineTransactionOutputTrait: EngineTransactionOutputTrait<O>,
    impl IEngineTransactionTrait: EngineTransactionTrait<
        T, I, O, IEngineTransactionInputTrait, IEngineTransactionOutputTrait
    >
>(
    ref engine: Engine<T>
) -> Result<(), felt252> {
    let mut cond = op_cond_false;
    if engine.cond_stack.branch_executing() {
        let ok = engine.pop_if_bool()?;
        if !ok {
            cond = op_cond_true;
        }
    } else {
        cond = op_cond_skip;
    }
    engine.cond_stack.push(cond);
    return Result::Ok(());
}

pub fn opcode_else<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    if engine.cond_stack.len() == 0 {
        return Result::Err('opcode_else: no matching if');
    }

    engine.cond_stack.swap_condition();
    return Result::Ok(());
}

pub fn opcode_endif<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    if engine.cond_stack.len() == 0 {
        return Result::Err('opcode_endif: no matching if');
    }

    engine.cond_stack.pop()?;
    return Result::Ok(());
}

pub fn opcode_verify<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    abstract_verify(ref engine)?;
    return Result::Ok(());
}

pub fn opcode_return<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    return Result::Err('opcode_return: returned early');
}

// stack.cairo

pub fn opcode_toaltstack<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let value = engine.dstack.pop_byte_array()?;
    engine.astack.push_byte_array(value);
    return Result::Ok(());
}

pub fn opcode_fromaltstack<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let a = engine.astack.pop_byte_array()?;
    engine.dstack.push_byte_array(a);
    return Result::Ok(());
}

pub fn opcode_depth<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let depth: i64 = engine.dstack.len().into();
    engine.dstack.push_int(depth);
    return Result::Ok(());
}

pub fn opcode_drop<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    engine.dstack.pop_byte_array()?;
    return Result::Ok(());
}

pub fn opcode_dup<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    engine.dstack.dup_n(1)?;
    return Result::Ok(());
}

pub fn opcode_swap<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let a = engine.dstack.pop_byte_array()?;
    let b = engine.dstack.pop_byte_array()?;
    engine.dstack.push_byte_array(a);
    engine.dstack.push_byte_array(b);
    return Result::Ok(());
}

pub fn opcode_nip<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    engine.dstack.nip_n(1)?;
    return Result::Ok(());
}

pub fn opcode_pick<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let a = engine.dstack.pop_int()?;
    engine.dstack.pick_n(ScriptNum::to_int32(a))?;

    return Result::Ok(());
}

pub fn opcode_ifdup<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let a = engine.dstack.peek_byte_array(0)?;

    if byte_array_to_bool(@a) {
        engine.dstack.push_byte_array(a);
    }
    return Result::Ok(());
}

pub fn opcode_tuck<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    engine.dstack.tuck()?;
    return Result::Ok(());
}

pub fn opcode_2drop<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    engine.dstack.pop_byte_array()?;
    engine.dstack.pop_byte_array()?;
    return Result::Ok(());
}

pub fn opcode_2dup<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    engine.dstack.dup_n(2)?;
    return Result::Ok(());
}

pub fn opcode_3dup<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    engine.dstack.dup_n(3)?;
    return Result::Ok(());
}

pub fn opcode_2swap<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let a = engine.dstack.pop_byte_array()?;
    let b = engine.dstack.pop_byte_array()?;
    let c = engine.dstack.pop_byte_array()?;
    let d = engine.dstack.pop_byte_array()?;
    engine.dstack.push_byte_array(b);
    engine.dstack.push_byte_array(a);
    engine.dstack.push_byte_array(d);
    engine.dstack.push_byte_array(c);
    return Result::Ok(());
}

pub fn opcode_2rot<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    engine.dstack.rot_n(2)?;
    return Result::Ok(());
}

pub fn opcode_rot<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    engine.dstack.rot_n(1)?;
    return Result::Ok(());
}

pub fn opcode_roll<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let value = engine.dstack.pop_int()?;
    engine.dstack.roll_n(ScriptNum::to_int32(value))?;
    return Result::Ok(());
}

pub fn opcode_over<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    engine.dstack.over_n(1)?;
    return Result::Ok(());
}

pub fn opcode_2over<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    engine.dstack.over_n(2)?;
    return Result::Ok(());
}

// splice.cairo

pub fn opcode_size<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let top_element = engine.dstack.peek_byte_array(0)?;
    engine.dstack.push_int(top_element.len().into());
    return Result::Ok(());
}

// bitwise.cairo

pub fn opcode_equal<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let a = engine.dstack.pop_byte_array()?;
    let b = engine.dstack.pop_byte_array()?;
    engine.dstack.push_bool(if a == b {
        true
    } else {
        false
    });
    return Result::Ok(());
}

pub fn opcode_equal_verify<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    opcode_equal(ref engine)?;
    abstract_verify(ref engine)?;
    return Result::Ok(());
}

// arithmetic.cairo

pub fn opcode_1add<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let value = engine.dstack.pop_int()?;
    let result = value + 1;
    engine.dstack.push_int(result);
    return Result::Ok(());
}

pub fn opcode_1sub<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let a = engine.dstack.pop_int()?;
    engine.dstack.push_int(a - 1);
    return Result::Ok(());
}

pub fn opcode_negate<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let a = engine.dstack.pop_int()?;
    engine.dstack.push_int(-a);
    return Result::Ok(());
}

pub fn opcode_abs<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let value = engine.dstack.pop_int()?;
    let abs_value = if value < 0 {
        -value
    } else {
        value
    };
    engine.dstack.push_int(abs_value);
    return Result::Ok(());
}

pub fn opcode_not<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let m = engine.dstack.pop_int()?;
    if m == 0 {
        engine.dstack.push_bool(true);
    } else {
        engine.dstack.push_bool(false);
    }
    return Result::Ok(());
}

pub fn opcode_0_not_equal<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let a = engine.dstack.pop_int()?;

    engine.dstack.push_int(if a != 0 {
        1
    } else {
        0
    });
    return Result::Ok(());
}

pub fn opcode_add<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let a = engine.dstack.pop_int()?;
    let b = engine.dstack.pop_int()?;
    engine.dstack.push_int(a + b);
    return Result::Ok(());
}

pub fn opcode_sub<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let a = engine.dstack.pop_int()?;
    let b = engine.dstack.pop_int()?;
    engine.dstack.push_int(b - a);
    return Result::Ok(());
}

pub fn opcode_bool_and<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let a = engine.dstack.pop_int()?;
    let b = engine.dstack.pop_int()?;
    engine.dstack.push_bool(if a != 0 && b != 0 {
        true
    } else {
        false
    });
    return Result::Ok(());
}

pub fn opcode_bool_or<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let a = engine.dstack.pop_int()?;
    let b = engine.dstack.pop_int()?;

    engine.dstack.push_bool(if a != 0 || b != 0 {
        true
    } else {
        false
    });
    return Result::Ok(());
}

pub fn opcode_numequal<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let a = engine.dstack.pop_int()?;
    let b = engine.dstack.pop_int()?;
    engine.dstack.push_bool(if a == b {
        true
    } else {
        false
    });
    return Result::Ok(());
}

pub fn opcode_numequalverify<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    opcode_numequal(ref engine)?;
    abstract_verify(ref engine)?;
    return Result::Ok(());
}

pub fn opcode_numnotequal<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let a = engine.dstack.pop_int()?;
    let b = engine.dstack.pop_int()?;
    engine.dstack.push_bool(if a != b {
        true
    } else {
        false
    });
    return Result::Ok(());
}

pub fn opcode_lessthan<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let a = engine.dstack.pop_int()?;
    let b = engine.dstack.pop_int()?;
    engine.dstack.push_bool(if b < a {
        true
    } else {
        false
    });
    return Result::Ok(());
}

pub fn opcode_greater_than<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let a = engine.dstack.pop_int()?;
    let b = engine.dstack.pop_int()?;
    engine.dstack.push_bool(if b > a {
        true
    } else {
        false
    });
    return Result::Ok(());
}

pub fn opcode_less_than_or_equal<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let v0 = engine.dstack.pop_int()?;
    let v1 = engine.dstack.pop_int()?;

    if v1 <= v0 {
        engine.dstack.push_bool(true);
    } else {
        engine.dstack.push_bool(false);
    }
    return Result::Ok(());
}

pub fn opcode_greater_than_or_equal<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let v0 = engine.dstack.pop_int()?;
    let v1 = engine.dstack.pop_int()?;

    if v1 >= v0 {
        engine.dstack.push_bool(true);
    } else {
        engine.dstack.push_bool(false);
    }
    return Result::Ok(());
}

pub fn opcode_min<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let a = engine.dstack.pop_int()?;
    let b = engine.dstack.pop_int()?;

    engine.dstack.push_int(if a < b {
        a
    } else {
        b
    });
    return Result::Ok(());
}

pub fn opcode_max<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let a = engine.dstack.pop_int()?;
    let b = engine.dstack.pop_int()?;
    engine.dstack.push_int(if a > b {
        a
    } else {
        b
    });
    return Result::Ok(());
}

pub fn opcode_within<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let max = engine.dstack.pop_int()?;
    let min = engine.dstack.pop_int()?;
    let value = engine.dstack.pop_int()?;
    engine.dstack.push_bool(if value >= min && value < max {
        true
    } else {
        false
    });
    return Result::Ok(());
}

// signature.cairo

use starknet::SyscallResultTrait;
use starknet::secp256_trait::{Secp256Trait, Signature, is_valid_signature};
use starknet::secp256k1::{Secp256k1Point};

//`BaseSigVerifier` is used to verify ECDSA signatures encoded in DER or BER format (pre-SegWit sig)
#[derive(Drop)]
pub struct BaseSigVerifier {
    // public key as a point on the secp256k1 curve, used to verify the signature
    pub_key: Secp256k1Point,
    // ECDSA signature
    sig: Signature,
    // raw byte array of the signature
    sig_bytes: @ByteArray,
    // raw byte array of the public key
    pk_bytes: @ByteArray,
    // part of the script being verified
    sub_script: ByteArray,
    // specifies how the transaction was hashed for signing
    hash_type: u32,
}

pub trait BaseSigVerifierTrait<
    I,
    O,
    T,
    +EngineTransactionInputTrait<I>,
    +EngineTransactionOutputTrait<O>,
    +EngineTransactionTrait<T, I, O>
> {
    fn new(
        ref vm: Engine<T>, sig_bytes: @ByteArray, pk_bytes: @ByteArray
    ) -> Result<BaseSigVerifier, felt252>;
    fn verify(ref self: BaseSigVerifier, ref vm: Engine<T>) -> bool;
}

impl BaseSigVerifierImpl<
    I,
    O,
    T,
    impl IEngineTransactionInput: EngineTransactionInputTrait<I>,
    impl IEngineTransactionOutput: EngineTransactionOutputTrait<O>,
    impl IEngineTransaction: EngineTransactionTrait<
        T, I, O, IEngineTransactionInput, IEngineTransactionOutput
    >,
    +Drop<I>,
    +Drop<O>,
    +Drop<T>
> of BaseSigVerifierTrait<I, O, T> {
    fn new(
        ref vm: Engine<T>, sig_bytes: @ByteArray, pk_bytes: @ByteArray
    ) -> Result<BaseSigVerifier, felt252> {
        let (pub_key, sig, hash_type) = parse_base_sig_and_pk(ref vm, pk_bytes, sig_bytes)?;
        let sub_script = vm.sub_script();
        Result::Ok(BaseSigVerifier { pub_key, sig, sig_bytes, pk_bytes, sub_script, hash_type })
    }

    // TODO: add signature cache mechanism for optimization
    fn verify(ref self: BaseSigVerifier, ref vm: Engine<T>) -> bool {
        let sub_script = remove_signature(@self.sub_script, self.sig_bytes);
        let sig_hash: u256 = calc_signature_hash::<
            I, O, T
        >(sub_script, self.hash_type, vm.transaction, vm.tx_idx);

        is_valid_signature(sig_hash, self.sig.r, self.sig.s, self.pub_key)
    }
}

pub trait BaseSegwitSigVerifierTrait<
    I,
    O,
    T,
    +EngineTransactionInputTrait<I>,
    +EngineTransactionOutputTrait<O>,
    +EngineTransactionTrait<T, I, O>
> {
    fn verify(ref self: BaseSigVerifier, ref vm: Engine<T>) -> bool;
}

impl BaseSegwitSigVerifierImpl<
    I,
    O,
    T,
    impl IEngineTransactionInput: EngineTransactionInputTrait<I>,
    impl IEngineTransactionOutput: EngineTransactionOutputTrait<O>,
    impl IEngineTransaction: EngineTransactionTrait<
        T, I, O, IEngineTransactionInput, IEngineTransactionOutput
    >,
    +Drop<I>,
    +Drop<O>,
    +Drop<T>
> of BaseSegwitSigVerifierTrait<I, O, T> {
    fn verify(ref self: BaseSigVerifier, ref vm: Engine<T>) -> bool {
        let sig_hashes = SigHashMidstateTrait::new(vm.transaction);
        let sig_hash: u256 = calc_witness_signature_hash::<
            I, O, T
        >(@self.sub_script, @sig_hashes, self.hash_type, vm.transaction, vm.tx_idx, vm.amount);

        is_valid_signature(sig_hash, self.sig.r, self.sig.s, self.pub_key)
    }
}

// Compares a slice of a byte array with the provided signature bytes to check for a match.
//
// @param script The byte array representing the script to be checked.
// @param sig_bytes The byte array containing the signature to compare against.
// @param i The starting index in the script where the comparison begins.
// @param push_data A byte that represents the length of the data segment to compare.
// @return `true` if the slice of the script matches the signature, `false` otherwise.
pub fn compare_data(script: @ByteArray, sig_bytes: @ByteArray, i: u32, push_data: u8) -> bool {
    let mut j: usize = 0;
    let mut len: usize = push_data.into();
    let mut found = true;

    while j != len {
        if script[i + j + 1] != sig_bytes[j] {
            found = false;
            break;
        }
        j += 1;
    };
    found
}

// Check if hash_type obeys scrict encoding requirements.
pub fn check_hash_type_encoding<
    T,
    +Drop<T>,
    I,
    +Drop<I>,
    impl IEngineTransactionInputTrait: EngineTransactionInputTrait<I>,
    O,
    +Drop<O>,
    impl IEngineTransactionOutputTrait: EngineTransactionOutputTrait<O>,
    impl IEngineTransactionTrait: EngineTransactionTrait<
        T, I, O, IEngineTransactionInputTrait, IEngineTransactionOutputTrait
    >
>(
    ref vm: Engine<T>, mut hash_type: u32
) -> Result<(), felt252> {
    if !vm.has_flag(ScriptFlags::ScriptVerifyStrictEncoding) {
        return Result::Ok(());
    }

    if hash_type > SIG_HASH_ANYONECANPAY {
        hash_type -= SIG_HASH_ANYONECANPAY;
    }

    if hash_type < SIG_HASH_ALL || hash_type > SIG_HASH_SINGLE {
        return Result::Err('invalid hash type');
    }

    return Result::Ok(());
}

// Check if signature obeys strict encoding requirements.
//
// This function checks the provided signature byte array (`sig_bytes`) against several
// encoding rules, including ASN.1 structure, length constraints, and other strict encoding
// requirements. It ensures the signature is properly formatted according to DER (Distinguished
// Encoding Rules) if required, and also checks the "low S" requirement if applicable.
//
// @param vm A reference to the `Engine` that manages the execution context and provides
//           the necessary script verification flags.
// @param sig_bytes The byte array containing the ECDSA signature that needs to be validated.

pub fn check_signature_encoding<
    T,
    +Drop<T>,
    I,
    +Drop<I>,
    impl IEngineTransactionInputTrait: EngineTransactionInputTrait<I>,
    O,
    +Drop<O>,
    impl IEngineTransactionOutputTrait: EngineTransactionOutputTrait<O>,
    impl IEngineTransactionTrait: EngineTransactionTrait<
        T, I, O, IEngineTransactionInputTrait, IEngineTransactionOutputTrait
    >
>(
    ref vm: Engine<T>, sig_bytes: @ByteArray, strict_encoding: bool
) -> Result<(), felt252> {
    let low_s = vm.has_flag(ScriptFlags::ScriptVerifyLowS);

    // ASN.1 identifiers for sequence and integer types.*
    let asn1_sequence_id: u8 = 0x30;
    let asn1_integer_id: u8 = 0x02;
    // Offsets used to parse the signature byte array.
    let sequence_offset: usize = 0;
    let data_len_offset: usize = 1;
    let data_offset: usize = 2;
    let r_type_offset: usize = 2;
    let r_len_offset: usize = 3;
    let r_offset: usize = 4;
    // Length of the signature byte array.
    let sig_bytes_len: usize = sig_bytes.len();
    // Check if the signature is empty.
    if sig_bytes_len == 0 {
        return Result::Err('invalid sig fmt: empty sig');
    }
    // Calculate the actual length of the signature, excluding the hash type.
    let sig_len = sig_bytes_len - HASH_TYPE_LEN;
    // Check if the signature is too short.
    if sig_len < MIN_SIG_LEN {
        return Result::Err('invalid sig fmt: too short');
    }
    // Check if the signature is too long.
    if sig_len > MAX_SIG_LEN {
        return Result::Err('invalid sig fmt: too long');
    }
    // Ensure the signature starts with the correct ASN.1 sequence identifier.
    if sig_bytes[sequence_offset] != asn1_sequence_id {
        return Result::Err('invalid sig fmt: wrong type');
    }
    // Verify that the length field matches the expected length.
    if sig_bytes[data_len_offset] != (sig_len - data_offset).try_into().unwrap() {
        return Result::Err('invalid sig fmt: bad length');
    }
    // Determine the length of the `R` value in the signature.
    let r_len: usize = sig_bytes[r_len_offset].into();
    let s_type_offset = r_offset + r_len;
    let s_len_offset = s_type_offset + 1;
    // Check if the `S` type offset exceeds the length of the signature.
    if s_type_offset > sig_len {
        return Result::Err('invalid sig fmt: S type missing');
    }
    // Check if the `S` length offset exceeds the length of the signature.
    if s_len_offset > sig_len {
        return Result::Err('invalid sig fmt: miss S length');
    }
    // Calculate the offset and length of the `S` value.
    let s_offset = s_len_offset + 1;
    let s_len: usize = sig_bytes[s_len_offset].into();
    // Ensure the `R` value is correctly identified as an ASN.1 integer.
    if sig_bytes[r_type_offset] != asn1_integer_id {
        return Result::Err('invalid sig fmt:R ASN.1');
    }
    // Validate the length of the `R` value.
    if r_len <= 0 || r_len > sig_len - r_offset - 3 {
        return Result::Err('invalid sig fmt:R length');
    }
    // If strict encoding is enforced, check for negative or excessively padded `R` values.
    if strict_encoding {
        if sig_bytes[r_offset] & 0x80 != 0 {
            return Result::Err('invalid sig fmt: negative R');
        }

        if r_len > 1 && sig_bytes[r_offset] == 0 && sig_bytes[r_offset + 1] & 0x80 == 0 {
            return Result::Err('invalid sig fmt: R padding');
        }
    }
    // Ensure the `S` value is correctly identified as an ASN.1 integer.
    if sig_bytes[s_type_offset] != asn1_integer_id {
        return Result::Err('invalid sig fmt:S ASN.1');
    }
    // Validate the length of the `S` value.
    if s_len <= 0 || s_len > sig_len - s_offset {
        return Result::Err('invalid sig fmt:S length');
    }
    // If strict encoding is enforced, check for negative or excessively padded `S` values.
    if strict_encoding {
        if sig_bytes[s_offset] & 0x80 != 0 {
            return Result::Err('invalid sig fmt: negative S');
        }

        if s_len > 1 && sig_bytes[s_offset] == 0 && sig_bytes[s_offset + 1] & 0x80 == 0 {
            return Result::Err('invalid sig fmt: S padding');
        }
    }
    // If the "low S" rule is enforced, check that the `S` value is below the threshold.
    if low_s {
        let s_value = u256_from_byte_array_with_offset(sig_bytes, s_offset, 32);
        let mut half_order = Secp256Trait::<Secp256k1Point>::get_curve_size();

        let (half_order_high_upper, half_order_high_lower) = DivRem::div_rem(half_order.high, 2);
        let carry = half_order_high_lower;
        half_order.low = (half_order.low / 2) + (carry * (MAX_U128 / 2 + 1));
        half_order.high = half_order_high_upper;

        if s_value > half_order {
            return Result::Err('sig not canonical high S value');
        }
    }

    return Result::Ok(());
}

// Checks if a public key is compressed based on its byte array representation.
// ie: 33 bytes, starts with 0x02 or 0x03, indicating ECP parity of the Y coord.
pub fn is_compressed_pub_key(pk_bytes: @ByteArray) -> bool {
    if pk_bytes.len() == 33 && (pk_bytes[0] == 0x02 || pk_bytes[0] == 0x03) {
        return true;
    }
    return false;
}

fn is_supported_pub_key_type(pk_bytes: @ByteArray) -> bool {
    if is_compressed_pub_key(pk_bytes) {
        return true;
    }

    // Uncompressed pub key
    if pk_bytes.len() == 65 && pk_bytes[0] == 0x04 {
        return true;
    }

    return false;
}

// Checks if a public key adheres to specific encoding rules based on the engine flags.
pub fn check_pub_key_encoding<
    T,
    +Drop<T>,
    I,
    +Drop<I>,
    impl IEngineTransactionInputTrait: EngineTransactionInputTrait<I>,
    O,
    +Drop<O>,
    impl IEngineTransactionOutputTrait: EngineTransactionOutputTrait<O>,
    impl IEngineTransactionTrait: EngineTransactionTrait<
        T, I, O, IEngineTransactionInputTrait, IEngineTransactionOutputTrait
    >
>(
    ref vm: Engine<T>, pk_bytes: @ByteArray
) -> Result<(), felt252> {
    if vm.has_flag(ScriptFlags::ScriptVerifyWitnessPubKeyType)
        && vm.is_witness_active(0)
        && !is_compressed_pub_key(pk_bytes) {
        return Result::Err(Error::WITNESS_PUBKEYTYPE);
    }

    if !vm.has_flag(ScriptFlags::ScriptVerifyStrictEncoding) {
        return Result::Ok(());
    }

    if !is_supported_pub_key_type(pk_bytes) {
        return Result::Err('unsupported public key type');
    }

    return Result::Ok(());
}

// Parses a public key byte array into a `Secp256k1Point` on the secp256k1 elliptic curve.
//
// This function processes the provided public key byte array (`pk_bytes`) and converts it into a
// `Secp256k1Point` object, which represents the public key as a point on the secp256k1 elliptic
// curve. Supports both compressed and uncompressed public keys.
//
// @param pk_bytes The byte array representing the public key to be parsed.
// @return A `Secp256k1Point` representing the public key on the secp256k1 elliptic curve.
pub fn parse_pub_key(pk_bytes: @ByteArray) -> Result<Secp256k1Point, felt252> {
    let mut pk_bytes_uncompressed = pk_bytes.clone();

    if is_compressed_pub_key(pk_bytes) {
        // Extract X coordinate and determine parity from prefix byte.
        let mut parity: bool = false;
        let pub_key: u256 = u256_from_byte_array_with_offset(pk_bytes, 1, 32);

        if pk_bytes[0] == 0x03 {
            parity = true;
        }
        return Result::Ok(
            Secp256Trait::<Secp256k1Point>::secp256_ec_get_point_from_x_syscall(pub_key, parity)
                .unwrap_syscall()
                .expect('Secp256k1Point: Invalid point.')
        );
    } else {
        // Extract X coordinate and determine parity from last byte.
        if pk_bytes_uncompressed.len() != 65 {
            return Result::Err('Invalid public key length');
        }
        let pub_key: u256 = u256_from_byte_array_with_offset(@pk_bytes_uncompressed, 1, 32);
        let parity = !(pk_bytes_uncompressed[64] & 1 == 0);

        return Result::Ok(
            Secp256Trait::<Secp256k1Point>::secp256_ec_get_point_from_x_syscall(pub_key, parity)
                .unwrap_syscall()
                .expect('Secp256k1Point: Invalid point.')
        );
    }
}

// Parses a DER-encoded ECDSA signature byte array into a `Signature` struct.
//
// This function extracts the `r` and `s` values from a DER-encoded ECDSA signature (`sig_bytes`).
// The function performs various checks to ensure the integrity and validity of the signature.
pub fn parse_signature(sig_bytes: @ByteArray) -> Result<Signature, felt252> {
    let mut sig_len: usize = sig_bytes.len() - HASH_TYPE_LEN;
    let mut r_len: usize = sig_bytes[3].into();
    let mut s_len: usize = sig_bytes[r_len + 5].into();
    let mut r_offset = 4;
    let mut s_offset = 6 + r_len;
    let order: u256 = Secp256Trait::<Secp256k1Point>::get_curve_size();

    let mut i = 0;

    //Strip leading zero
    while s_len != 0 && sig_bytes[i + r_len + 6] == 0x00 {
        sig_len -= 1;
        s_len -= 1;
        s_offset += 1;
        i += 1;
    };

    let s_sig: u256 = u256_from_byte_array_with_offset(sig_bytes, s_offset, s_len);

    i = 0;

    while r_len != 0 && sig_bytes[i + 4] == 0x00 {
        sig_len -= 1;
        r_len -= 1;
        r_offset += 1;
        i += 1;
    };

    let r_sig: u256 = u256_from_byte_array_with_offset(sig_bytes, r_offset, r_len);

    if r_len > 32 {
        return Result::Err('invalid sig: R > 256 bits');
    }
    if r_sig >= order {
        return Result::Err('invalid sig: R >= group order');
    }
    if r_sig == 0 {
        return Result::Err('invalid sig: R is zero');
    }
    if s_len > 32 {
        return Result::Err('invalid sig: S > 256 bits');
    }
    if s_sig >= order {
        return Result::Err('invalid sig: S >= group order');
    }
    if s_sig == 0 {
        return Result::Err('invalid sig: S is zero');
    }
    if sig_len != r_len + s_len + 6 {
        return Result::Err('invalid sig: bad final length');
    }
    return Result::Ok(Signature { r: r_sig, s: s_sig, y_parity: false, });
}

// Parses the public key and signature byte arrays based on consensus rules.
// Returning a tuple containing the parsed public key, signature, and hash type.
pub fn parse_base_sig_and_pk<
    T,
    +Drop<T>,
    I,
    +Drop<I>,
    impl IEngineTransactionInputTrait: EngineTransactionInputTrait<I>,
    O,
    +Drop<O>,
    impl IEngineTransactionOutputTrait: EngineTransactionOutputTrait<O>,
    impl IEngineTransactionTrait: EngineTransactionTrait<
        T, I, O, IEngineTransactionInputTrait, IEngineTransactionOutputTrait
    >
>(
    ref vm: Engine<T>, pk_bytes: @ByteArray, sig_bytes: @ByteArray
) -> Result<(Secp256k1Point, Signature, u32), felt252> {
    let verify_der = vm.has_flag(ScriptFlags::ScriptVerifyDERSignatures);
    let strict_encoding = vm.has_flag(ScriptFlags::ScriptVerifyStrictEncoding) || verify_der;
    if sig_bytes.len() == 0 {
        return if strict_encoding {
            Result::Err(Error::SCRIPT_ERR_SIG_DER)
        } else {
            Result::Err('empty signature')
        };
    }

    // TODO: strct encoding
    let hash_type_offset: usize = sig_bytes.len() - 1;
    let hash_type: u32 = sig_bytes[hash_type_offset].into();
    if let Result::Err(e) = check_hash_type_encoding(ref vm, hash_type) {
        return if verify_der {
            Result::Err(Error::SCRIPT_ERR_SIG_DER)
        } else {
            Result::Err(e)
        };
    }
    if let Result::Err(e) = check_signature_encoding(ref vm, sig_bytes, strict_encoding) {
        return if verify_der {
            Result::Err(Error::SCRIPT_ERR_SIG_DER)
        } else {
            Result::Err(e)
        };
    }

    if let Result::Err(e) = check_pub_key_encoding(ref vm, pk_bytes) {
        return if verify_der {
            Result::Err(Error::SCRIPT_ERR_SIG_DER)
        } else {
            Result::Err(e)
        };
    }

    let pub_key = match parse_pub_key(pk_bytes) {
        Result::Ok(key) => key,
        Result::Err(e) => if verify_der {
            return Result::Err(Error::SCRIPT_ERR_SIG_DER);
        } else {
            return Result::Err(e);
        },
    };

    let sig = match parse_signature(sig_bytes) {
        Result::Ok(signature) => signature,
        Result::Err(e) => if verify_der {
            return Result::Err(Error::SCRIPT_ERR_SIG_DER);
        } else {
            return Result::Err(e);
        },
    };

    Result::Ok((pub_key, sig, hash_type))
}

// Removes the ECDSA signature from a given script.
pub fn remove_signature(script: @ByteArray, sig_bytes: @ByteArray) -> @ByteArray {
    if script.len() == 0 || sig_bytes.len() == 0 {
        return script;
    }

    let mut processed_script: ByteArray = "";
    let mut i: usize = 0;

    let script_len = script.len();
    while i < script_len {
        let opcode = script[i];
        let data_len = data_len(script, i).unwrap();
        let end = i + data_len + 1;
        if data_len == sig_bytes.len() {
            let mut found = compare_data(script, sig_bytes, i, opcode);
            if found {
                i = end;
                continue;
            }
        }
        while i != end {
            processed_script.append_byte(script[i]);
            i += 1;
        };
    };

    @processed_script
}

// constant.cairo

// Represents the default signature hash type, often treated as `SIG_HASH_ALL`, ensuring that all
// inputs and outputs of the transaction are signed to provide complete protection against
// unauthorized modifications.
pub const SIG_HASH_DEFAULT: u32 = 0x0;
//Sign all inputs and outputs of the transaction, making it the most secure and commonly used hash
//type that ensures the entire transaction is covered by the signature, preventing any changes after
//signing.
pub const SIG_HASH_ALL: u32 = 0x1;
//Sign all inputs but none of the outputs, allowing outputs to be modified after signing, which is
//useful in scenarios requiring flexible transaction outputs without invalidating the signature.
pub const SIG_HASH_NONE: u32 = 0x2;
//Sign only the input being signed and its corresponding output, enabling partial transaction
//signatures where each input is responsible for its associated output, useful for independent input
//signing.
pub const SIG_HASH_SINGLE: u32 = 0x3;
//Allows signing of only one input, leaving others unsigned, often used with other hash types for
//creating transactions that can be extended with additional inputs by different parties without
//invalidating the signature.
pub const SIG_HASH_ANYONECANPAY: u32 = 0x80;
//Mask to isolate the base signature hash type from a combined hash type that might include
//additional flags like `SIG_HASH_ANYONECANPAY`, ensuring accurate identification and processing of
//the core hash type.
pub const SIG_HASH_MASK: u32 = 0x1f;
//Base version number for Segregated Witness (SegWit) transactions, representing the initial version
//of SegWit that enables more efficient transaction validation by separating signature data from the
//main transaction body.
pub const BASE_SEGWIT_WITNESS_VERSION: u32 = 0x0;
//Minimum valid length for a DER-encoded ECDSA signature, ensuring that signatures meet the minimum
//required length for validity, as shorter signatures could indicate an incomplete or malformed
//signature.
pub const MIN_SIG_LEN: usize = 8;
//Maximum valid length for a DER-encoded ECDSA signature, ensuring that signatures do not exceed the
//expected length, which could indicate corruption or the inclusion of invalid data within the
//signature.
pub const MAX_SIG_LEN: usize = 72;
//Length of the byte that specifies the signature hash type in a signature, determining how the
//transaction was hashed before signing and influencing which parts of the transaction are covered
//by the signature.
pub const HASH_TYPE_LEN: usize = 1;
//Length of the witness program for P2WPKH (Pay-to-Witness-Public-Key-Hash) scripts in SegWit,
//including the version byte and the public key hash, ensuring correct data formatting and inclusion
//in SegWit transactions.
pub const WITNESS_V0_PUB_KEY_HASH_LEN: usize = 22;

pub const MAX_U128: u128 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;
pub const MAX_U32: u32 = 0xFFFFFFFF;

// utils.cairo

// Removes `OP_CODESEPARATOR` opcodes from the `script`.
// By removing this opcode, the script becomes suitable for hashing and signature verification.
pub fn remove_opcodeseparator(script: @ByteArray) -> @ByteArray {
    let mut parsed_script: ByteArray = "";
    let mut i: usize = 0;

    // TODO: tokenizer/standardize script parsing
    let script_len = script.len();
    while i < script_len {
        let opcode = script[i];
        // TODO: Error handling
        if opcode == Opcode::OP_CODESEPARATOR {
            i += 1;
            continue;
        }
        let data_len = data_len(script, i).unwrap();
        let end = i + data_len + 1;
        while i != end {
            parsed_script.append_byte(script[i]);
            i += 1;
        }
    };

    @parsed_script
}

// Prepares a modified copy of the transaction, ready for signature hashing.
//
// This function processes a transaction by modifying its inputs and outputs according to the hash
// type, which determines which parts of the transaction are included in the signature hash.
//
// @param transaction The original transaction to be processed.
// @param index The index of the current input being processed.
// @param signature_script The script that is added to the transaction input during processing.
// @param hash_type The hash type that dictates how the transaction should be modified.
// @return A modified copy of the transaction based on the provided hash type.
pub fn transaction_procedure<
    I,
    O,
    T,
    impl IEngineTransactionInputTrait: EngineTransactionInputTrait<I>,
    impl IEngineTransactionOutputTrait: EngineTransactionOutputTrait<O>,
    impl IEngineTransactionTrait: EngineTransactionTrait<
        T, I, O, IEngineTransactionInputTrait, IEngineTransactionOutputTrait
    >,
    +Drop<O>,
    +Drop<I>,
    +Drop<T>,
>(
    transaction: @T, index: u32, signature_script: ByteArray, hash_type: u32
) -> EngineTransaction {
    let hash_type_masked = hash_type & SIG_HASH_MASK;
    let mut transaction_inputs_clone = array![];
    for input in transaction
        .get_transaction_inputs() {
            let new_transaction_input = EngineTransactionInput {
                previous_outpoint: EngineOutPoint {
                    txid: input.get_prevout_txid(), vout: input.get_prevout_vout()
                },
                signature_script: input.get_signature_script().clone(),
                witness: input.get_witness().into(),
                sequence: input.get_sequence()
            };
            transaction_inputs_clone.append(new_transaction_input);
        };
    let mut transaction_outputs_clone = array![];
    for output in transaction
        .get_transaction_outputs() {
            let new_transaction_output = EngineTransactionOutput {
                value: output.get_value(), publickey_script: output.get_publickey_script().clone()
            };
            transaction_outputs_clone.append(new_transaction_output);
        };
    let mut transaction_copy = EngineTransaction {
        version: transaction.get_version(),
        transaction_inputs: transaction_inputs_clone,
        transaction_outputs: transaction_outputs_clone,
        locktime: transaction.get_locktime()
    };
    let mut i: usize = 0;
    let mut transaction_input: Array<EngineTransactionInput> = transaction_copy.transaction_inputs;
    let mut processed_transaction_input: Array<EngineTransactionInput> = ArrayTrait::<
        EngineTransactionInput
    >::new();
    let mut processed_transaction_output: Array<EngineTransactionOutput> = ArrayTrait::<
        EngineTransactionOutput
    >::new();

    let tx_input_len = transaction_input.len();
    while i != tx_input_len {
        // TODO: Optimize this
        let mut temp_transaction_input: EngineTransactionInput = transaction_input[i].clone();

        if hash_type_masked == SIG_HASH_SINGLE && i < index {
            processed_transaction_output
                .append(EngineTransactionOutput { value: -1, publickey_script: "", });
        }

        if i == index {
            processed_transaction_input
                .append(
                    EngineTransactionInput {
                        previous_outpoint: temp_transaction_input.previous_outpoint,
                        signature_script: signature_script.clone(),
                        witness: temp_transaction_input.witness.clone(),
                        sequence: temp_transaction_input.sequence
                    }
                );
        } else {
            if hash_type & SIG_HASH_ANYONECANPAY != 0 {
                continue;
            }
            let mut temp_sequence = temp_transaction_input.sequence;
            if hash_type_masked == SIG_HASH_NONE
                || hash_type_masked == SIG_HASH_SINGLE {
                temp_sequence = 0;
            }
            processed_transaction_input
                .append(
                    EngineTransactionInput {
                        previous_outpoint: temp_transaction_input.previous_outpoint,
                        signature_script: "",
                        witness: temp_transaction_input.witness.clone(),
                        sequence: temp_sequence
                    }
                );
        }

        i += 1;
    };

    transaction_copy.transaction_inputs = processed_transaction_input;

    if hash_type_masked == SIG_HASH_NONE {
        transaction_copy.transaction_outputs = ArrayTrait::<EngineTransactionOutput>::new();
    }

    if hash_type_masked == SIG_HASH_SINGLE {
        transaction_copy.transaction_outputs = processed_transaction_output;
    }

    transaction_copy
}

// Checks if the given script is a Pay-to-Witness-Public-Key-Hash (P2WPKH) script.
// A P2WPKH script has a length of 22 bytes and starts with a version byte (`0x00`)
// followed by a 20-byte public key hash.
//
// Thus, a Pay-to-Witness-Public-Key-Hash script is of the form:
// `OP_0 OP_DATA_20 <20-byte public key hash>`
pub fn is_witness_pub_key_hash(script: @ByteArray) -> bool {
    if script.len() == WITNESS_V0_PUB_KEY_HASH_LEN
        && script[0] == Opcode::OP_0
        && script[1] == Opcode::OP_DATA_20 {
        return true;
    }
    false
}

// sighash.cairo

// Calculates the signature hash for specified transaction data and hash type.
pub fn calc_signature_hash<
    I,
    O,
    T,
    impl IEngineTransactionInput: EngineTransactionInputTrait<I>,
    impl IEngineTransactionOutput: EngineTransactionOutputTrait<O>,
    impl IEngineTransaction: EngineTransactionTrait<
        T, I, O, IEngineTransactionInput, IEngineTransactionOutput
    >,
    +Drop<I>,
    +Drop<O>,
    +Drop<T>
>(
    sub_script: @ByteArray, hash_type: u32, transaction: @T, tx_idx: u32
) -> u256 {
    let transaction_outputs_len: usize = transaction.get_transaction_outputs().len();
    // `SIG_HASH_SINGLE` only signs corresponding input/output pair.
    // The original Satoshi client gave a signature hash of 0x01 in cases where the input index
    // was out of bounds. This buggy/dangerous behavior is part of the consensus rules,
    // and would require a hard fork to fix.
    if hash_type & SIG_HASH_MASK == SIG_HASH_SINGLE
        && tx_idx >= transaction_outputs_len {
        return 0x01;
    }

    // Remove any OP_CODESEPARATOR opcodes from the subscript.
    let mut signature_script: @ByteArray = remove_opcodeseparator(sub_script);
    // Create a modified copy of the transaction according to the hash type.
    let transaction_copy: EngineTransaction = transaction_procedure(
        transaction, tx_idx, signature_script.clone(), hash_type
    );

    let mut sig_hash_bytes: ByteArray = transaction_copy.serialize_no_witness();
    sig_hash_bytes.append_word_rev(hash_type.into(), 4);

    // Hash and return the serialized transaction data twice using SHA-256.
    double_sha256(@sig_hash_bytes)
}

// Calculates the signature hash for a Segregated Witness (SegWit) transaction and hash type.
pub fn calc_witness_signature_hash<
    I,
    O,
    T,
    impl IEngineTransactionInput: EngineTransactionInputTrait<I>,
    impl IEngineTransactionOutput: EngineTransactionOutputTrait<O>,
    impl IEngineTransaction: EngineTransactionTrait<
        T, I, O, IEngineTransactionInput, IEngineTransactionOutput
    >,
    +Drop<I>,
    +Drop<O>,
    +Drop<T>
>(
    sub_script: @ByteArray,
    sig_hashes: @SegwitSigHashMidstate,
    hash_type: u32,
    transaction: @T,
    tx_idx: u32,
    amount: i64
) -> u256 {
    // TODO: Bounds check?

    let mut sig_hash_bytes: ByteArray = "";
    sig_hash_bytes.append_word_rev(transaction.get_version().into(), 4);

    let zero: u256 = 0;
    if hash_type & SIG_HASH_ANYONECANPAY == 0 {
        let hash_prevouts_v0: u256 = *sig_hashes.hash_prevouts_v0;
        sig_hash_bytes.append_word(hash_prevouts_v0.high.into(), 16);
        sig_hash_bytes.append_word(hash_prevouts_v0.low.into(), 16);
    } else {
        sig_hash_bytes.append_word(zero.high.into(), 16);
        sig_hash_bytes.append_word(zero.low.into(), 16);
    }

    if hash_type & SIG_HASH_ANYONECANPAY == 0
        && hash_type & SIG_HASH_MASK != SIG_HASH_SINGLE
        && hash_type & SIG_HASH_MASK != SIG_HASH_NONE {
        let hash_sequence_v0: u256 = *sig_hashes.hash_sequence_v0;
        sig_hash_bytes.append_word(hash_sequence_v0.high.into(), 16);
        sig_hash_bytes.append_word(hash_sequence_v0.low.into(), 16);
    } else {
        sig_hash_bytes.append_word(zero.high.into(), 16);
        sig_hash_bytes.append_word(zero.low.into(), 16);
    }

    let input = transaction.get_transaction_inputs().at(tx_idx);
    sig_hash_bytes.append_word(input.get_prevout_txid().high.into(), 16);
    sig_hash_bytes.append_word(input.get_prevout_txid().low.into(), 16);
    sig_hash_bytes.append_word_rev(input.get_prevout_vout().into(), 4);

    if is_witness_pub_key_hash(sub_script) {
        // P2WKH with 0x19 OP_DUP OP_HASH160 OP_DATA_20 <pubkey hash> OP_EQUALVERIFY OP_CHECKSIG
        sig_hash_bytes.append_byte(0x19);
        sig_hash_bytes.append_byte(Opcode::OP_DUP);
        sig_hash_bytes.append_byte(Opcode::OP_HASH160);
        sig_hash_bytes.append_byte(Opcode::OP_DATA_20);
        let subscript_len = sub_script.len();
        // TODO: extractWitnessPubKeyHash
        let mut i: usize = 2;
        while i != subscript_len {
            sig_hash_bytes.append_byte(sub_script[i]);
            i += 1;
        };
        sig_hash_bytes.append_byte(Opcode::OP_EQUALVERIFY);
        sig_hash_bytes.append_byte(Opcode::OP_CHECKSIG);
    } else {
        write_var_int(ref sig_hash_bytes, sub_script.len().into());
        sig_hash_bytes.append(sub_script);
    }

    sig_hash_bytes.append_word_rev(amount.into(), 8);
    sig_hash_bytes.append_word_rev(input.get_sequence().into(), 4);

    if hash_type & SIG_HASH_MASK != SIG_HASH_SINGLE
        && hash_type & SIG_HASH_MASK != SIG_HASH_NONE {
        let hash_outputs_v0: u256 = *sig_hashes.hash_outputs_v0;
        sig_hash_bytes.append_word(hash_outputs_v0.high.into(), 16);
        sig_hash_bytes.append_word(hash_outputs_v0.low.into(), 16);
    } else if hash_type & SIG_HASH_MASK == SIG_HASH_SINGLE
        && tx_idx < transaction.get_transaction_outputs().len() {
        let output = transaction.get_transaction_outputs().at(tx_idx);
        let mut output_bytes: ByteArray = "";
        output_bytes.append_word_rev(output.get_value().into(), 8);
        write_var_int(ref output_bytes, output.get_publickey_script().len().into());
        output_bytes.append(output.get_publickey_script());
        let hashed_output: u256 = double_sha256(@output_bytes);
        sig_hash_bytes.append_word(hashed_output.high.into(), 16);
        sig_hash_bytes.append_word(hashed_output.low.into(), 16);
    } else {
        sig_hash_bytes.append_word(zero.high.into(), 16);
        sig_hash_bytes.append_word(zero.low.into(), 16);
    }

    sig_hash_bytes.append_word_rev(transaction.get_locktime().into(), 4);
    sig_hash_bytes.append_word_rev(hash_type.into(), 4);

    double_sha256(@sig_hash_bytes)
}

// locktime.cairo

const LOCKTIME_THRESHOLD: u32 = 500000000; // Nov 5 00:53:20 1985 UTC
const SEQUENCE_LOCKTIME_DISABLED: u32 = 0x80000000;
const SEQUENCE_LOCKTIME_IS_SECOND: u32 = 0x00400000;
const SEQUENCE_LOCKTIME_MASK: u32 = 0x0000FFFF;
const SEQUENCE_MAX: u32 = 0xFFFFFFFF;

fn verify_locktime(tx_locktime: i64, threshold: i64, stack_locktime: i64) -> Result<(), felt252> {
    // Check if 'tx_locktime' and 'locktime' are same type (locktime or height)
    if !((tx_locktime < threshold && stack_locktime < threshold)
        || (tx_locktime >= threshold && stack_locktime >= threshold)) {
        return Result::Err(Error::UNSATISFIED_LOCKTIME);
    }

    // Check validity
    if stack_locktime > tx_locktime {
        return Result::Err(Error::UNSATISFIED_LOCKTIME);
    }

    Result::Ok(())
}

pub fn opcode_checklocktimeverify<
    T,
    +Drop<T>,
    I,
    +Drop<I>,
    impl IEngineTransactionInputTrait: EngineTransactionInputTrait<I>,
    O,
    +Drop<O>,
    impl IEngineTransactionOutputTrait: EngineTransactionOutputTrait<O>,
    impl IEngineTransactionTrait: EngineTransactionTrait<
        T, I, O, IEngineTransactionInputTrait, IEngineTransactionOutputTrait
    >
>(
    ref engine: Engine<T>
) -> Result<(), felt252> {
    if !engine.has_flag(ScriptFlags::ScriptVerifyCheckLockTimeVerify) {
        if engine.has_flag(ScriptFlags::ScriptDiscourageUpgradableNops) {
            return Result::Err(Error::SCRIPT_DISCOURAGE_UPGRADABLE_NOPS);
        }
        // Behave as OP_NOP
        return Result::Ok(());
    }

    let tx_locktime: i64 = EngineTransactionTrait::<
        T, I, O, IEngineTransactionInputTrait, IEngineTransactionOutputTrait
    >::get_locktime(engine.transaction)
        .into();
    // Get locktime as 5 byte integer because 'tx_locktime' is u32
    let stack_locktime: i64 = ScriptNum::try_into_num_n_bytes(
        engine.dstack.peek_byte_array(0)?, 5, engine.dstack.verify_minimal_data
    )?;

    if stack_locktime < 0 {
        return Result::Err(Error::UNSATISFIED_LOCKTIME);
    }

    // Check if tx sequence is not 'SEQUENCE_MAX' else if tx may be considered as finalized and the
    // behavior of OP_CHECKLOCKTIMEVERIFY can be bypassed
    let transaction_input = EngineTransactionTrait::<
        T, I, O, IEngineTransactionInputTrait, IEngineTransactionOutputTrait
    >::get_transaction_inputs(engine.transaction)
        .at(engine.tx_idx);
    let sequence = EngineTransactionInputTrait::<I>::get_sequence(transaction_input);
    if sequence == SEQUENCE_MAX {
        return Result::Err(Error::FINALIZED_TX_CLTV);
    }

    verify_locktime(tx_locktime, LOCKTIME_THRESHOLD.into(), stack_locktime)
}

pub fn opcode_checksequenceverify<
    T,
    +Drop<T>,
    I,
    +Drop<I>,
    impl IEngineTransactionInputTrait: EngineTransactionInputTrait<I>,
    O,
    +Drop<O>,
    impl IEngineTransactionOutputTrait: EngineTransactionOutputTrait<O>,
    impl IEngineTransactionTrait: EngineTransactionTrait<
        T, I, O, IEngineTransactionInputTrait, IEngineTransactionOutputTrait
    >
>(
    ref engine: Engine<T>
) -> Result<(), felt252> {
    if !engine.has_flag(ScriptFlags::ScriptVerifyCheckSequenceVerify) {
        if engine.has_flag(ScriptFlags::ScriptDiscourageUpgradableNops) {
            return Result::Err(Error::SCRIPT_DISCOURAGE_UPGRADABLE_NOPS);
        }
        // Behave as OP_NOP
        return Result::Ok(());
    }

    // Get sequence as 5 byte integer because 'sequence' is u32
    let stack_sequence: i64 = ScriptNum::try_into_num_n_bytes(
        engine.dstack.peek_byte_array(0)?, 5, engine.dstack.verify_minimal_data
    )?;

    if stack_sequence < 0 {
        return Result::Err(Error::UNSATISFIED_LOCKTIME);
    }

    // Redefine 'stack_sequence' to perform bitwise operation easily
    let stack_sequence_u32: u32 = stack_sequence.try_into().unwrap();

    // Disabled bit set in 'stack_sequence' result as OP_NOP behavior
    if stack_sequence_u32 & SEQUENCE_LOCKTIME_DISABLED != 0 {
        return Result::Ok(());
    }

    // Prevent trigger OP_CHECKSEQUENCEVERIFY before tx version 2
    let version = EngineTransactionTrait::<
        T, I, O, IEngineTransactionInputTrait, IEngineTransactionOutputTrait
    >::get_version(engine.transaction);
    if version < 2 {
        return Result::Err(Error::INVALID_TX_VERSION);
    }

    let transaction_input = EngineTransactionTrait::<
        T, I, O, IEngineTransactionInputTrait, IEngineTransactionOutputTrait
    >::get_transaction_inputs(engine.transaction)
        .at(engine.tx_idx);
    let tx_sequence: u32 = EngineTransactionInputTrait::<I>::get_sequence(transaction_input);

    // Disabled bit set in 'tx_sequence' result is an error
    if tx_sequence & SEQUENCE_LOCKTIME_DISABLED != 0 {
        return Result::Err(Error::UNSATISFIED_LOCKTIME);
    }

    // Mask off non-consensus bits before comparisons
    let locktime_mask = SEQUENCE_LOCKTIME_IS_SECOND | SEQUENCE_LOCKTIME_MASK;
    verify_locktime(
        (tx_sequence & locktime_mask).into(),
        SEQUENCE_LOCKTIME_IS_SECOND.into(),
        (stack_sequence_u32 & locktime_mask).into()
    )
}

// crypto.cairo

const MAX_KEYS_PER_MULTISIG: i64 = 20;

pub fn opcode_sha256<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let arr = @engine.dstack.pop_byte_array()?;
    let res = sha256_byte_array(arr);
    engine.dstack.push_byte_array(res);
    return Result::Ok(());
}

pub fn opcode_hash160<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let m = engine.dstack.pop_byte_array()?;
    let res = sha256_byte_array(@m);
    let h: ByteArray = ripemd160_hash(@res).into();
    engine.dstack.push_byte_array(h);
    return Result::Ok(());
}

pub fn opcode_hash256<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let m = engine.dstack.pop_byte_array()?;
    let res = double_sha256_bytearray(@m);
    engine.dstack.push_byte_array(res.into());
    return Result::Ok(());
}

pub fn opcode_ripemd160<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let m = engine.dstack.pop_byte_array()?;
    let h: ByteArray = ripemd160_hash(@m).into();
    engine.dstack.push_byte_array(h);
    return Result::Ok(());
}

pub fn opcode_checksig<
    T,
    +Drop<T>,
    I,
    +Drop<I>,
    impl IEngineTransactionInputTrait: EngineTransactionInputTrait<I>,
    O,
    +Drop<O>,
    impl IEngineTransactionOutputTrait: EngineTransactionOutputTrait<O>,
    impl IEngineTransactionTrait: EngineTransactionTrait<
        T, I, O, IEngineTransactionInputTrait, IEngineTransactionOutputTrait
    >
>(
    ref engine: Engine<T>
) -> Result<(), felt252> {
    let pk_bytes = engine.dstack.pop_byte_array()?;
    let full_sig_bytes = engine.dstack.pop_byte_array()?;

    if full_sig_bytes.len() < 1 {
        engine.dstack.push_bool(false);
        return Result::Ok(());
    }

    let mut is_valid: bool = false;
    if engine.witness_program.len() == 0 {
        // Base Signature Verification
        let res = BaseSigVerifierTrait::new(ref engine, @full_sig_bytes, @pk_bytes);
        if res.is_err() {
            let err = res.unwrap_err();
            if err == Error::SCRIPT_ERR_SIG_DER || err == Error::WITNESS_PUBKEYTYPE {
                return Result::Err(err);
            };
            engine.dstack.push_bool(false);
            return Result::Ok(());
        }

        let mut sig_verifier = res.unwrap();
        if BaseSigVerifierTrait::verify(ref sig_verifier, ref engine) {
            is_valid = true;
        } else {
            is_valid = false;
        }
    } else if engine.is_witness_active(0) {
        // Witness Signature Verification
        let res = BaseSigVerifierTrait::new(ref engine, @full_sig_bytes, @pk_bytes);
        if res.is_err() {
            let err = res.unwrap_err();
            if err == Error::SCRIPT_ERR_SIG_DER || err == Error::WITNESS_PUBKEYTYPE {
                return Result::Err(err);
            };
            engine.dstack.push_bool(false);
            return Result::Ok(());
        }

        let mut sig_verifier = res.unwrap();
        if BaseSegwitSigVerifierTrait::verify(ref sig_verifier, ref engine) {
            is_valid = true;
        } else {
            is_valid = false;
        }
    } // TODO: Add Taproot verification

    if !is_valid && engine.has_flag(ScriptFlags::ScriptVerifyNullFail) && full_sig_bytes.len() > 0 {
        return Result::Err(Error::SIG_NULLFAIL);
    }

    engine.dstack.push_bool(is_valid);
    return Result::Ok(());
}

pub fn opcode_checkmultisig<
    T,
    +Drop<T>,
    I,
    +Drop<I>,
    impl IEngineTransactionInputTrait: EngineTransactionInputTrait<I>,
    O,
    +Drop<O>,
    impl IEngineTransactionOutputTrait: EngineTransactionOutputTrait<O>,
    impl IEngineTransactionTrait: EngineTransactionTrait<
        T, I, O, IEngineTransactionInputTrait, IEngineTransactionOutputTrait
    >
>(
    ref engine: Engine<T>
) -> Result<(), felt252> {
    // TODO Error on taproot exec

    let verify_der = engine.has_flag(ScriptFlags::ScriptVerifyDERSignatures);
    // Get number of public keys and construct array
    let num_keys = engine.dstack.pop_int()?;
    let mut num_pub_keys: i64 = ScriptNum::to_int32(num_keys).into();
    if num_pub_keys < 0 {
        return Result::Err('check multisig: num pk < 0');
    }
    if num_pub_keys > MAX_KEYS_PER_MULTISIG {
        return Result::Err('check multisig: num pk > max');
    }
    engine.num_ops += num_pub_keys.try_into().unwrap();
    if engine.num_ops > 201 { // TODO: Hardcoded limit
        return Result::Err(Error::SCRIPT_TOO_MANY_OPERATIONS);
    }
    let mut pub_keys = ArrayTrait::<ByteArray>::new();
    let mut i: i64 = 0;
    let mut err: felt252 = 0;
    while i != num_pub_keys {
        match engine.dstack.pop_byte_array() {
            Result::Ok(pk) => pub_keys.append(pk),
            Result::Err(e) => err = e
        };
        i += 1;
    };
    if err != 0 {
        return Result::Err(err);
    }

    // Get number of required sigs and construct array
    let num_sig_base = engine.dstack.pop_int()?;
    let mut num_sigs: i64 = ScriptNum::to_int32(num_sig_base).into();
    if num_sigs < 0 {
        return Result::Err('check multisig: num sigs < 0');
    }
    if num_sigs > num_pub_keys {
        return Result::Err('check multisig: num sigs > pk');
    }
    let mut sigs = ArrayTrait::<ByteArray>::new();
    i = 0;
    err = 0;
    while i != num_sigs {
        match engine.dstack.pop_byte_array() {
            Result::Ok(s) => sigs.append(s),
            Result::Err(e) => err = e
        };
        i += 1;
    };
    if err != 0 {
        return Result::Err(err);
    }

    // Historical bug
    let dummy = engine.dstack.pop_byte_array()?;

    if engine.has_flag(ScriptFlags::ScriptStrictMultiSig) && dummy.len() != 0 {
        return Result::Err(Error::SCRIPT_STRICT_MULTISIG);
    }

    let mut script = engine.sub_script();

    let mut s: u32 = 0;
    let end = sigs.len();
    while s != end {
        script = remove_signature(@script, sigs.at(s)).clone();
        s += 1;
    };

    let mut success = true;
    num_pub_keys += 1; // Offset due to decrementing it in the loop
    let mut pub_key_idx: i64 = -1;
    let mut sig_idx: i64 = 0;

    while num_sigs != 0 {
        pub_key_idx += 1;
        num_pub_keys -= 1;
        if num_sigs > num_pub_keys {
            success = false;
            break;
        }

        let sig = sigs.at(sig_idx.try_into().unwrap());
        let pub_key = pub_keys.at(pub_key_idx.try_into().unwrap());
        if sig.len() == 0 {
            continue;
        }
        let res = parse_base_sig_and_pk(ref engine, pub_key, sig);
        if res.is_err() {
            success = false;
            err = res.unwrap_err();
            break;
        }

        let (parsed_pub_key, parsed_sig, hash_type) = res.unwrap();
        let sig_hash: u256 = calc_signature_hash(
            @script, hash_type, engine.transaction, engine.tx_idx
        );

        if is_valid_signature(sig_hash, parsed_sig.r, parsed_sig.s, parsed_pub_key) {
            sig_idx += 1;
            num_sigs -= 1;
        }
    };

    if err != 0 {
        return Result::Err(err);
    }

    if !success {
        if engine.has_flag(ScriptFlags::ScriptVerifyNullFail) {
            let mut err = '';
            for s in sigs {
                if s.len() > 0 {
                    err = Error::SIG_NULLFAIL;
                    break;
                }
            };
            if err != '' {
                return Result::Err(err);
            }
        } else if verify_der {
            return Result::Err(Error::SCRIPT_ERR_SIG_DER);
        }
    }

    engine.dstack.push_bool(success);
    Result::Ok(())
}

pub fn opcode_codeseparator<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    engine.last_code_sep = engine.opcode_idx;

    // TODO Disable OP_CODESEPARATOR for non-segwit scripts.
    // if engine.witness_program.len() == 0 &&
    // engine.has_flag(ScriptFlags::ScriptVerifyConstScriptCode) {

    // return Result::Err('opcode_codeseparator:non-segwit');
    // }

    Result::Ok(())
}

pub fn opcode_checksigverify<
    T,
    +Drop<T>,
    I,
    +Drop<I>,
    impl IEngineTransactionInputTrait: EngineTransactionInputTrait<I>,
    O,
    +Drop<O>,
    impl IEngineTransactionOutputTrait: EngineTransactionOutputTrait<O>,
    impl IEngineTransactionTrait: EngineTransactionTrait<
        T, I, O, IEngineTransactionInputTrait, IEngineTransactionOutputTrait
    >
>(
    ref engine: Engine<T>
) -> Result<(), felt252> {
    opcode_checksig(ref engine)?;
    abstract_verify(ref engine)?;
    return Result::Ok(());
}

pub fn opcode_checkmultisigverify<
    T,
    +Drop<T>,
    I,
    +Drop<I>,
    impl IEngineTransactionInputTrait: EngineTransactionInputTrait<I>,
    O,
    +Drop<O>,
    impl IEngineTransactionOutputTrait: EngineTransactionOutputTrait<O>,
    impl IEngineTransactionTrait: EngineTransactionTrait<
        T, I, O, IEngineTransactionInputTrait, IEngineTransactionOutputTrait
    >
>(
    ref engine: Engine<T>
) -> Result<(), felt252> {
    opcode_checkmultisig(ref engine)?;
    abstract_verify(ref engine)?;
    return Result::Ok(());
}

pub fn opcode_sha1<T, +Drop<T>>(ref engine: Engine<T>) -> Result<(), felt252> {
    let m = engine.dstack.pop_byte_array()?;
    let h: ByteArray = sha1_hashs(@m).into();
    engine.dstack.push_byte_array(h);
    return Result::Ok(());
}


//Opcode.cairo

pub mod Opcode {
    pub const OP_0: u8 = 0;
    pub const OP_FALSE: u8 = 0;
    pub const OP_DATA_1: u8 = 1;
    pub const OP_DATA_2: u8 = 2;
    pub const OP_DATA_3: u8 = 3;
    pub const OP_DATA_4: u8 = 4;
    pub const OP_DATA_5: u8 = 5;
    pub const OP_DATA_6: u8 = 6;
    pub const OP_DATA_7: u8 = 7;
    pub const OP_DATA_8: u8 = 8;
    pub const OP_DATA_9: u8 = 9;
    pub const OP_DATA_10: u8 = 10;
    pub const OP_DATA_11: u8 = 11;
    pub const OP_DATA_12: u8 = 12;
    pub const OP_DATA_13: u8 = 13;
    pub const OP_DATA_14: u8 = 14;
    pub const OP_DATA_15: u8 = 15;
    pub const OP_DATA_16: u8 = 16;
    pub const OP_DATA_17: u8 = 17;
    pub const OP_DATA_18: u8 = 18;
    pub const OP_DATA_19: u8 = 19;
    pub const OP_DATA_20: u8 = 20;
    pub const OP_DATA_21: u8 = 21;
    pub const OP_DATA_22: u8 = 22;
    pub const OP_DATA_23: u8 = 23;
    pub const OP_DATA_24: u8 = 24;
    pub const OP_DATA_25: u8 = 25;
    pub const OP_DATA_26: u8 = 26;
    pub const OP_DATA_27: u8 = 27;
    pub const OP_DATA_28: u8 = 28;
    pub const OP_DATA_29: u8 = 29;
    pub const OP_DATA_30: u8 = 30;
    pub const OP_DATA_31: u8 = 31;
    pub const OP_DATA_32: u8 = 32;
    pub const OP_DATA_33: u8 = 33;
    pub const OP_DATA_34: u8 = 34;
    pub const OP_DATA_35: u8 = 35;
    pub const OP_DATA_36: u8 = 36;
    pub const OP_DATA_37: u8 = 37;
    pub const OP_DATA_38: u8 = 38;
    pub const OP_DATA_39: u8 = 39;
    pub const OP_DATA_40: u8 = 40;
    pub const OP_DATA_41: u8 = 41;
    pub const OP_DATA_42: u8 = 42;
    pub const OP_DATA_43: u8 = 43;
    pub const OP_DATA_44: u8 = 44;
    pub const OP_DATA_45: u8 = 45;
    pub const OP_DATA_46: u8 = 46;
    pub const OP_DATA_47: u8 = 47;
    pub const OP_DATA_48: u8 = 48;
    pub const OP_DATA_49: u8 = 49;
    pub const OP_DATA_50: u8 = 50;
    pub const OP_DATA_51: u8 = 51;
    pub const OP_DATA_52: u8 = 52;
    pub const OP_DATA_53: u8 = 53;
    pub const OP_DATA_54: u8 = 54;
    pub const OP_DATA_55: u8 = 55;
    pub const OP_DATA_56: u8 = 56;
    pub const OP_DATA_57: u8 = 57;
    pub const OP_DATA_58: u8 = 58;
    pub const OP_DATA_59: u8 = 59;
    pub const OP_DATA_60: u8 = 60;
    pub const OP_DATA_61: u8 = 61;
    pub const OP_DATA_62: u8 = 62;
    pub const OP_DATA_63: u8 = 63;
    pub const OP_DATA_64: u8 = 64;
    pub const OP_DATA_65: u8 = 65;
    pub const OP_DATA_66: u8 = 66;
    pub const OP_DATA_67: u8 = 67;
    pub const OP_DATA_68: u8 = 68;
    pub const OP_DATA_69: u8 = 69;
    pub const OP_DATA_70: u8 = 70;
    pub const OP_DATA_71: u8 = 71;
    pub const OP_DATA_72: u8 = 72;
    pub const OP_DATA_73: u8 = 73;
    pub const OP_DATA_74: u8 = 74;
    pub const OP_DATA_75: u8 = 75;
    pub const OP_PUSHDATA1: u8 = 76;
    pub const OP_PUSHDATA2: u8 = 77;
    pub const OP_PUSHDATA4: u8 = 78;
    pub const OP_1NEGATE: u8 = 79;
    pub const OP_RESERVED: u8 = 80;
    pub const OP_TRUE: u8 = 81;
    pub const OP_1: u8 = 81;
    pub const OP_2: u8 = 82;
    pub const OP_3: u8 = 83;
    pub const OP_4: u8 = 84;
    pub const OP_5: u8 = 85;
    pub const OP_6: u8 = 86;
    pub const OP_7: u8 = 87;
    pub const OP_8: u8 = 88;
    pub const OP_9: u8 = 89;
    pub const OP_10: u8 = 90;
    pub const OP_11: u8 = 91;
    pub const OP_12: u8 = 92;
    pub const OP_13: u8 = 93;
    pub const OP_14: u8 = 94;
    pub const OP_15: u8 = 95;
    pub const OP_16: u8 = 96;
    pub const OP_NOP: u8 = 97;
    pub const OP_VER: u8 = 98;
    pub const OP_IF: u8 = 99;
    pub const OP_NOTIF: u8 = 100;
    pub const OP_VERIF: u8 = 101;
    pub const OP_VERNOTIF: u8 = 102;
    pub const OP_ELSE: u8 = 103;
    pub const OP_ENDIF: u8 = 104;
    pub const OP_VERIFY: u8 = 105;
    pub const OP_RETURN: u8 = 106;
    pub const OP_TOALTSTACK: u8 = 107;
    pub const OP_FROMALTSTACK: u8 = 108;
    pub const OP_2DROP: u8 = 109;
    pub const OP_2DUP: u8 = 110;
    pub const OP_3DUP: u8 = 111;
    pub const OP_2OVER: u8 = 112;
    pub const OP_2ROT: u8 = 113;
    pub const OP_2SWAP: u8 = 114;
    pub const OP_IFDUP: u8 = 115;
    pub const OP_DEPTH: u8 = 116;
    pub const OP_DROP: u8 = 117;
    pub const OP_DUP: u8 = 118;
    pub const OP_NIP: u8 = 119;
    pub const OP_OVER: u8 = 120;
    pub const OP_PICK: u8 = 121;
    pub const OP_ROLL: u8 = 122;
    pub const OP_ROT: u8 = 123;
    pub const OP_SWAP: u8 = 124;
    pub const OP_TUCK: u8 = 125;
    pub const OP_CAT: u8 = 126;
    pub const OP_SUBSTR: u8 = 127;
    pub const OP_LEFT: u8 = 128;
    pub const OP_RIGHT: u8 = 129;
    pub const OP_SIZE: u8 = 130;
    pub const OP_INVERT: u8 = 131;
    pub const OP_AND: u8 = 132;
    pub const OP_OR: u8 = 133;
    pub const OP_XOR: u8 = 134;
    pub const OP_EQUAL: u8 = 135;
    pub const OP_EQUALVERIFY: u8 = 136;
    pub const OP_RESERVED1: u8 = 137;
    pub const OP_RESERVED2: u8 = 138;
    pub const OP_1ADD: u8 = 139;
    pub const OP_1SUB: u8 = 140;
    pub const OP_2MUL: u8 = 141;
    pub const OP_2DIV: u8 = 142;
    pub const OP_NEGATE: u8 = 143;
    pub const OP_ABS: u8 = 144;
    pub const OP_NOT: u8 = 145;
    pub const OP_0NOTEQUAL: u8 = 146;
    pub const OP_ADD: u8 = 147;
    pub const OP_SUB: u8 = 148;
    pub const OP_MUL: u8 = 149;
    pub const OP_DIV: u8 = 150;
    pub const OP_MOD: u8 = 151;
    pub const OP_LSHIFT: u8 = 152;
    pub const OP_RSHIFT: u8 = 153;
    pub const OP_BOOLAND: u8 = 154;
    pub const OP_BOOLOR: u8 = 155;
    pub const OP_NUMEQUAL: u8 = 156;
    pub const OP_NUMEQUALVERIFY: u8 = 157;
    pub const OP_NUMNOTEQUAL: u8 = 158;
    pub const OP_LESSTHAN: u8 = 159;
    pub const OP_GREATERTHAN: u8 = 160;
    pub const OP_LESSTHANOREQUAL: u8 = 161;
    pub const OP_GREATERTHANOREQUAL: u8 = 162;
    pub const OP_MIN: u8 = 163;
    pub const OP_MAX: u8 = 164;
    pub const OP_WITHIN: u8 = 165;
    pub const OP_RIPEMD160: u8 = 166;
    pub const OP_SHA1: u8 = 167;
    pub const OP_SHA256: u8 = 168;
    pub const OP_HASH160: u8 = 169;
    pub const OP_HASH256: u8 = 170;
    pub const OP_CODESEPARATOR: u8 = 171;
    pub const OP_CHECKSIG: u8 = 172;
    pub const OP_CHECKSIGVERIFY: u8 = 173;
    pub const OP_CHECKMULTISIG: u8 = 174;
    pub const OP_CHECKMULTISIGVERIFY: u8 = 175;
    pub const OP_NOP1: u8 = 176;
    pub const OP_NOP2: u8 = 177;
    pub const OP_CHECKLOCKTIMEVERIFY: u8 = 177;
    pub const OP_NOP3: u8 = 178;
    pub const OP_CHECKSEQUENCEVERIFY: u8 = 178;
    pub const OP_NOP4: u8 = 179;
    pub const OP_NOP5: u8 = 180;
    pub const OP_NOP6: u8 = 181;
    pub const OP_NOP7: u8 = 182;
    pub const OP_NOP8: u8 = 183;
    pub const OP_NOP9: u8 = 184;
    pub const OP_NOP10: u8 = 185;

    use super::opcode_false;
    use super::opcode_push_data;
    use super::opcode_push_data_x;
    use super::opcode_1negate;
    use super::opcode_reserved;
    use super::opcode_nop;
    use super::opcode_n;
    use super::opcode_if;
    use super::opcode_notif;
    use super::opcode_else;
    use super::opcode_endif;
    use super::opcode_verify;
    use super::opcode_return;
    use super::opcode_toaltstack;
    use super::opcode_fromaltstack;
    use super::opcode_2drop;
    use super::opcode_2dup;
    use super::opcode_3dup;
    use super::opcode_2over;
    use super::opcode_2rot;
    use super::opcode_2swap;
    use super::opcode_ifdup;
    use super::opcode_depth;
    use super::opcode_drop;
    use super::opcode_dup;
    use super::opcode_nip;
    use super::opcode_over;
    use super::opcode_disabled;
    use super::opcode_pick;
    use super::opcode_roll;
    use super::opcode_rot;
    use super::opcode_swap;
    use super::opcode_tuck;
    use super::opcode_size;
    use super::opcode_equal;
    use super::opcode_equal_verify;
    use super::opcode_1add;
    use super::opcode_1sub;
    use super::opcode_negate;
    use super::opcode_abs;
    use super::opcode_not;
    use super::opcode_0_not_equal;
    use super::opcode_add;
    use super::opcode_sub;
    use super::opcode_bool_and;
    use super::opcode_bool_or;
    use super::opcode_numequal;
    use super::opcode_numequalverify;
    use super::opcode_numnotequal;
    use super::opcode_lessthan;
    use super::opcode_greater_than;
    use super::opcode_less_than_or_equal;
    use super::opcode_greater_than_or_equal;
    use super::opcode_min;
    use super::opcode_max;
    use super::opcode_within;
    use super::opcode_ripemd160;
    use super::opcode_sha1;
    use super::opcode_sha256;
    use super::opcode_hash160;
    use super::opcode_hash256;
    use super::opcode_codeseparator;
    use super::opcode_checksig;
    use super::opcode_checksigverify;
    use super::opcode_checkmultisig;
    use super::opcode_checkmultisigverify;
    use super::opcode_checklocktimeverify;
    use super::opcode_checksequenceverify;
    use super::not_implemented;
    use super::EngineTransactionInputTrait;
    use super::EngineTransactionOutputTrait;
    use super::Engine;

    use super::EngineTransactionTrait;
    
    pub fn execute<
        T,
        +Drop<T>,
        I,
        +Drop<I>,
        impl IEngineTransactionInputTrait: EngineTransactionInputTrait<I>,
        O,
        +Drop<O>,
        impl IEngineTransactionOutputTrait: EngineTransactionOutputTrait<O>,
        impl IEngineTransactionTrait: EngineTransactionTrait<
            T, I, O, IEngineTransactionInputTrait, IEngineTransactionOutputTrait
        >
    >(
        opcode: u8, ref engine: Engine<T>
    ) -> Result<(), felt252> {
        match opcode {
            0 => opcode_false(ref engine),
            1 => opcode_push_data(1, ref engine),
            2 => opcode_push_data(2, ref engine),
            3 => opcode_push_data(3, ref engine),
            4 => opcode_push_data(4, ref engine),
            5 => opcode_push_data(5, ref engine),
            6 => opcode_push_data(6, ref engine),
            7 => opcode_push_data(7, ref engine),
            8 => opcode_push_data(8, ref engine),
            9 => opcode_push_data(9, ref engine),
            10 => opcode_push_data(10, ref engine),
            11 => opcode_push_data(11, ref engine),
            12 => opcode_push_data(12, ref engine),
            13 => opcode_push_data(13, ref engine),
            14 => opcode_push_data(14, ref engine),
            15 => opcode_push_data(15, ref engine),
            16 => opcode_push_data(16, ref engine),
            17 => opcode_push_data(17, ref engine),
            18 => opcode_push_data(18, ref engine),
            19 => opcode_push_data(19, ref engine),
            20 => opcode_push_data(20, ref engine),
            21 => opcode_push_data(21, ref engine),
            22 => opcode_push_data(22, ref engine),
            23 => opcode_push_data(23, ref engine),
            24 => opcode_push_data(24, ref engine),
            25 => opcode_push_data(25, ref engine),
            26 => opcode_push_data(26, ref engine),
            27 => opcode_push_data(27, ref engine),
            28 => opcode_push_data(28, ref engine),
            29 => opcode_push_data(29, ref engine),
            30 => opcode_push_data(30, ref engine),
            31 => opcode_push_data(31, ref engine),
            32 => opcode_push_data(32, ref engine),
            33 => opcode_push_data(33, ref engine),
            34 => opcode_push_data(34, ref engine),
            35 => opcode_push_data(35, ref engine),
            36 => opcode_push_data(36, ref engine),
            37 => opcode_push_data(37, ref engine),
            38 => opcode_push_data(38, ref engine),
            39 => opcode_push_data(39, ref engine),
            40 => opcode_push_data(40, ref engine),
            41 => opcode_push_data(41, ref engine),
            42 => opcode_push_data(42, ref engine),
            43 => opcode_push_data(43, ref engine),
            44 => opcode_push_data(44, ref engine),
            45 => opcode_push_data(45, ref engine),
            46 => opcode_push_data(46, ref engine),
            47 => opcode_push_data(47, ref engine),
            48 => opcode_push_data(48, ref engine),
            49 => opcode_push_data(49, ref engine),
            50 => opcode_push_data(50, ref engine),
            51 => opcode_push_data(51, ref engine),
            52 => opcode_push_data(52, ref engine),
            53 => opcode_push_data(53, ref engine),
            54 => opcode_push_data(54, ref engine),
            55 => opcode_push_data(55, ref engine),
            56 => opcode_push_data(56, ref engine),
            57 => opcode_push_data(57, ref engine),
            58 => opcode_push_data(58, ref engine),
            59 => opcode_push_data(59, ref engine),
            60 => opcode_push_data(60, ref engine),
            61 => opcode_push_data(61, ref engine),
            62 => opcode_push_data(62, ref engine),
            63 => opcode_push_data(63, ref engine),
            64 => opcode_push_data(64, ref engine),
            65 => opcode_push_data(65, ref engine),
            66 => opcode_push_data(66, ref engine),
            67 => opcode_push_data(67, ref engine),
            68 => opcode_push_data(68, ref engine),
            69 => opcode_push_data(69, ref engine),
            70 => opcode_push_data(70, ref engine),
            71 => opcode_push_data(71, ref engine),
            72 => opcode_push_data(72, ref engine),
            73 => opcode_push_data(73, ref engine),
            74 => opcode_push_data(74, ref engine),
            75 => opcode_push_data(75, ref engine),
            76 => opcode_push_data_x(1, ref engine),
            77 => opcode_push_data_x(2, ref engine),
            78 => opcode_push_data_x(4, ref engine),
            79 => opcode_1negate(ref engine),
            80 => opcode_reserved("reserved", ref engine),
            81 => opcode_n(1, ref engine),
            82 => opcode_n(2, ref engine),
            83 => opcode_n(3, ref engine),
            84 => opcode_n(4, ref engine),
            85 => opcode_n(5, ref engine),
            86 => opcode_n(6, ref engine),
            87 => opcode_n(7, ref engine),
            88 => opcode_n(8, ref engine),
            89 => opcode_n(9, ref engine),
            90 => opcode_n(10, ref engine),
            91 => opcode_n(11, ref engine),
            92 => opcode_n(12, ref engine),
            93 => opcode_n(13, ref engine),
            94 => opcode_n(14, ref engine),
            95 => opcode_n(15, ref engine),
            96 => opcode_n(16, ref engine),
            97 => opcode_nop(ref engine, 97),
            98 => opcode_reserved("ver", ref engine),
            99 => opcode_if(ref engine),
            100 => opcode_notif(ref engine),
            101 => opcode_reserved("verif", ref engine),
            102 => opcode_reserved("vernotif", ref engine),
            103 => opcode_else(ref engine),
            104 => opcode_endif(ref engine),
            105 => opcode_verify(ref engine),
            106 => opcode_return(ref engine),
            107 => opcode_toaltstack(ref engine),
            108 => opcode_fromaltstack(ref engine),
            109 => opcode_2drop(ref engine),
            110 => opcode_2dup(ref engine),
            111 => opcode_3dup(ref engine),
            112 => opcode_2over(ref engine),
            113 => opcode_2rot(ref engine),
            114 => opcode_2swap(ref engine),
            115 => opcode_ifdup(ref engine),
            116 => opcode_depth(ref engine),
            117 => opcode_drop(ref engine),
            118 => opcode_dup(ref engine),
            119 => opcode_nip(ref engine),
            120 => opcode_over(ref engine),
            121 => opcode_pick(ref engine),
            122 => opcode_roll(ref engine),
            123 => opcode_rot(ref engine),
            124 => opcode_swap(ref engine),
            125 => opcode_tuck(ref engine),
            126 => opcode_disabled(ref engine),
            127 => opcode_disabled(ref engine),
            128 => opcode_disabled(ref engine),
            129 => opcode_disabled(ref engine),
            130 => opcode_size(ref engine),
            131 => opcode_disabled(ref engine),
            132 => opcode_disabled(ref engine),
            133 => opcode_disabled(ref engine),
            134 => opcode_disabled(ref engine),
            135 => opcode_equal(ref engine),
            136 => opcode_equal_verify(ref engine),
            137 => opcode_reserved("reserved1", ref engine),
            138 => opcode_reserved("reserved2", ref engine),
            139 => opcode_1add(ref engine),
            140 => opcode_1sub(ref engine),
            141 => opcode_disabled(ref engine),
            142 => opcode_disabled(ref engine),
            143 => opcode_negate(ref engine),
            144 => opcode_abs(ref engine),
            145 => opcode_not(ref engine),
            146 => opcode_0_not_equal(ref engine),
            147 => opcode_add(ref engine),
            148 => opcode_sub(ref engine),
            149 => opcode_disabled(ref engine),
            150 => opcode_disabled(ref engine),
            151 => opcode_disabled(ref engine),
            152 => opcode_disabled(ref engine),
            153 => opcode_disabled(ref engine),
            154 => opcode_bool_and(ref engine),
            155 => opcode_bool_or(ref engine),
            156 => opcode_numequal(ref engine),
            157 => opcode_numequalverify(ref engine),
            158 => opcode_numnotequal(ref engine),
            159 => opcode_lessthan(ref engine),
            160 => opcode_greater_than(ref engine),
            161 => opcode_less_than_or_equal(ref engine),
            162 => opcode_greater_than_or_equal(ref engine),
            163 => opcode_min(ref engine),
            164 => opcode_max(ref engine),
            165 => opcode_within(ref engine),
            166 => opcode_ripemd160(ref engine),
            167 => opcode_sha1(ref engine),
            168 => opcode_sha256(ref engine),
            169 => opcode_hash160(ref engine),
            170 => opcode_hash256(ref engine),
            171 => opcode_codeseparator(ref engine),
            172 => opcode_checksig(ref engine),
            173 => opcode_checksigverify(ref engine),
            174 => opcode_checkmultisig(ref engine),
            175 => opcode_checkmultisigverify(ref engine),
            176 => opcode_nop(ref engine, 176),
            177 => opcode_checklocktimeverify(ref engine),
            178 => opcode_checksequenceverify(ref engine),
            179 => opcode_nop(ref engine, 179),
            180 => opcode_nop(ref engine, 180),
            181 => opcode_nop(ref engine, 181),
            182 => opcode_nop(ref engine, 182),
            183 => opcode_nop(ref engine, 183),
            184 => opcode_nop(ref engine, 184),
            185 => opcode_nop(ref engine, 185),
            _ => not_implemented(ref engine)
        }
    }

    pub fn is_opcode_disabled<T, +Drop<T>>(
        opcode: u8, ref engine: Engine<T>
    ) -> Result<(), felt252> {
        if opcode == OP_CAT
            || opcode == OP_SUBSTR
            || opcode == OP_LEFT
            || opcode == OP_RIGHT
            || opcode == OP_INVERT
            || opcode == OP_AND
            || opcode == OP_OR
            || opcode == OP_XOR
            || opcode == OP_2MUL
            || opcode == OP_2DIV
            || opcode == OP_MUL
            || opcode == OP_DIV
            || opcode == OP_MOD
            || opcode == OP_LSHIFT
            || opcode == OP_RSHIFT {
            return opcode_disabled(ref engine);
        } else {
            return Result::Ok(());
        }
    }

    pub fn is_opcode_always_illegal<T, +Drop<T>>(
        opcode: u8, ref engine: Engine<T>
    ) -> Result<(), felt252> {
        if opcode == OP_VERIF {
            return opcode_reserved("verif", ref engine);
        } else if opcode == OP_VERNOTIF {
            return opcode_reserved("vernotif", ref engine);
        } else {
            return Result::Ok(());
        }
    }

    pub fn is_data_opcode(opcode: u8) -> bool {
        return (opcode >= OP_DATA_1 && opcode <= OP_DATA_75);
    }

    pub fn is_push_opcode(opcode: u8) -> bool {
        return (opcode == OP_PUSHDATA1 || opcode == OP_PUSHDATA2 || opcode == OP_PUSHDATA4);
    }

    pub fn is_canonical_push(opcode: u8, data: @ByteArray) -> bool {
        let data_len = data.len();
        if opcode > OP_16 {
            return true;
        }

        if opcode < OP_PUSHDATA1 && opcode > OP_0 && data_len == 1 && data[0] <= 16 {
            // Could have used OP_N
            return false;
        } else if opcode == OP_PUSHDATA1 && data_len < OP_PUSHDATA1.into() {
            // Could have used OP_DATA_N
            return false;
        } else if opcode == OP_PUSHDATA2 && data_len <= 0xFF {
            // Could have used OP_PUSHDATA1
            return false;
        } else if opcode == OP_PUSHDATA4 && data_len <= 0xFFFF {
            // Could have used OP_PUSHDATA2
            return false;
        }

        return true;
    }

    pub fn is_branching_opcode(opcode: u8) -> bool {
        if opcode == OP_IF || opcode == OP_NOTIF || opcode == OP_ELSE || opcode == OP_ENDIF {
            return true;
        }
        return false;
    }
}

// Compiler.cairo

// Compiler that takes a Bitcoin Script program and compiles it into a bytecode
#[derive(Destruct)]
pub struct Compiler {
    // Dict containing opcode names to their bytecode representation
    opcodes: Felt252Dict<Nullable<u8>>
}

pub trait CompilerTrait {
    // Create a compiler, initializing the opcode dict
    fn new() -> Compiler;
    // Adds an opcode "OP_XXX" to the opcodes dict under: "OP_XXX" and "XXX"
    fn add_opcode(ref self: Compiler, name: felt252, opcode: u8);
    // Compiles a program like "OP_1 OP_2 OP_ADD" into a bytecode run by the Engine.
    fn compile(self: Compiler, script: ByteArray) -> Result<ByteArray, felt252>;
}

pub impl CompilerImpl of CompilerTrait {
    fn new() -> Compiler {
        let mut compiler = Compiler { opcodes: Default::default() };
        // Add the opcodes to the dict
        compiler.add_opcode('OP_0', Opcode::OP_0);
        compiler.add_opcode('OP_FALSE', Opcode::OP_FALSE);
        compiler.add_opcode('OP_DATA_1', Opcode::OP_DATA_1);
        compiler.add_opcode('OP_DATA_2', Opcode::OP_DATA_2);
        compiler.add_opcode('OP_DATA_3', Opcode::OP_DATA_3);
        compiler.add_opcode('OP_DATA_4', Opcode::OP_DATA_4);
        compiler.add_opcode('OP_DATA_5', Opcode::OP_DATA_5);
        compiler.add_opcode('OP_DATA_6', Opcode::OP_DATA_6);
        compiler.add_opcode('OP_DATA_7', Opcode::OP_DATA_7);
        compiler.add_opcode('OP_DATA_8', Opcode::OP_DATA_8);
        compiler.add_opcode('OP_DATA_9', Opcode::OP_DATA_9);
        compiler.add_opcode('OP_DATA_10', Opcode::OP_DATA_10);
        compiler.add_opcode('OP_DATA_11', Opcode::OP_DATA_11);
        compiler.add_opcode('OP_DATA_12', Opcode::OP_DATA_12);
        compiler.add_opcode('OP_DATA_13', Opcode::OP_DATA_13);
        compiler.add_opcode('OP_DATA_14', Opcode::OP_DATA_14);
        compiler.add_opcode('OP_DATA_15', Opcode::OP_DATA_15);
        compiler.add_opcode('OP_DATA_16', Opcode::OP_DATA_16);
        compiler.add_opcode('OP_DATA_17', Opcode::OP_DATA_17);
        compiler.add_opcode('OP_DATA_18', Opcode::OP_DATA_18);
        compiler.add_opcode('OP_DATA_19', Opcode::OP_DATA_19);
        compiler.add_opcode('OP_DATA_20', Opcode::OP_DATA_20);
        compiler.add_opcode('OP_DATA_21', Opcode::OP_DATA_21);
        compiler.add_opcode('OP_DATA_22', Opcode::OP_DATA_22);
        compiler.add_opcode('OP_DATA_23', Opcode::OP_DATA_23);
        compiler.add_opcode('OP_DATA_24', Opcode::OP_DATA_24);
        compiler.add_opcode('OP_DATA_25', Opcode::OP_DATA_25);
        compiler.add_opcode('OP_DATA_26', Opcode::OP_DATA_26);
        compiler.add_opcode('OP_DATA_27', Opcode::OP_DATA_27);
        compiler.add_opcode('OP_DATA_28', Opcode::OP_DATA_28);
        compiler.add_opcode('OP_DATA_29', Opcode::OP_DATA_29);
        compiler.add_opcode('OP_DATA_30', Opcode::OP_DATA_30);
        compiler.add_opcode('OP_DATA_31', Opcode::OP_DATA_31);
        compiler.add_opcode('OP_DATA_32', Opcode::OP_DATA_32);
        compiler.add_opcode('OP_DATA_33', Opcode::OP_DATA_33);
        compiler.add_opcode('OP_DATA_34', Opcode::OP_DATA_34);
        compiler.add_opcode('OP_DATA_35', Opcode::OP_DATA_35);
        compiler.add_opcode('OP_DATA_36', Opcode::OP_DATA_36);
        compiler.add_opcode('OP_DATA_37', Opcode::OP_DATA_37);
        compiler.add_opcode('OP_DATA_38', Opcode::OP_DATA_38);
        compiler.add_opcode('OP_DATA_39', Opcode::OP_DATA_39);
        compiler.add_opcode('OP_DATA_40', Opcode::OP_DATA_40);
        compiler.add_opcode('OP_DATA_41', Opcode::OP_DATA_41);
        compiler.add_opcode('OP_DATA_42', Opcode::OP_DATA_42);
        compiler.add_opcode('OP_DATA_43', Opcode::OP_DATA_43);
        compiler.add_opcode('OP_DATA_44', Opcode::OP_DATA_44);
        compiler.add_opcode('OP_DATA_45', Opcode::OP_DATA_45);
        compiler.add_opcode('OP_DATA_46', Opcode::OP_DATA_46);
        compiler.add_opcode('OP_DATA_47', Opcode::OP_DATA_47);
        compiler.add_opcode('OP_DATA_48', Opcode::OP_DATA_48);
        compiler.add_opcode('OP_DATA_49', Opcode::OP_DATA_49);
        compiler.add_opcode('OP_DATA_50', Opcode::OP_DATA_50);
        compiler.add_opcode('OP_DATA_51', Opcode::OP_DATA_51);
        compiler.add_opcode('OP_DATA_52', Opcode::OP_DATA_52);
        compiler.add_opcode('OP_DATA_53', Opcode::OP_DATA_53);
        compiler.add_opcode('OP_DATA_54', Opcode::OP_DATA_54);
        compiler.add_opcode('OP_DATA_55', Opcode::OP_DATA_55);
        compiler.add_opcode('OP_DATA_56', Opcode::OP_DATA_56);
        compiler.add_opcode('OP_DATA_57', Opcode::OP_DATA_57);
        compiler.add_opcode('OP_DATA_58', Opcode::OP_DATA_58);
        compiler.add_opcode('OP_DATA_59', Opcode::OP_DATA_59);
        compiler.add_opcode('OP_DATA_60', Opcode::OP_DATA_60);
        compiler.add_opcode('OP_DATA_61', Opcode::OP_DATA_61);
        compiler.add_opcode('OP_DATA_62', Opcode::OP_DATA_62);
        compiler.add_opcode('OP_DATA_63', Opcode::OP_DATA_63);
        compiler.add_opcode('OP_DATA_64', Opcode::OP_DATA_64);
        compiler.add_opcode('OP_DATA_65', Opcode::OP_DATA_65);
        compiler.add_opcode('OP_DATA_66', Opcode::OP_DATA_66);
        compiler.add_opcode('OP_DATA_67', Opcode::OP_DATA_67);
        compiler.add_opcode('OP_DATA_68', Opcode::OP_DATA_68);
        compiler.add_opcode('OP_DATA_69', Opcode::OP_DATA_69);
        compiler.add_opcode('OP_DATA_70', Opcode::OP_DATA_70);
        compiler.add_opcode('OP_DATA_71', Opcode::OP_DATA_71);
        compiler.add_opcode('OP_DATA_72', Opcode::OP_DATA_72);
        compiler.add_opcode('OP_DATA_73', Opcode::OP_DATA_73);
        compiler.add_opcode('OP_DATA_74', Opcode::OP_DATA_74);
        compiler.add_opcode('OP_DATA_75', Opcode::OP_DATA_75);
        compiler.add_opcode('OP_PUSHBYTES_0', Opcode::OP_0);
        compiler.add_opcode('OP_PUSHBYTES_1', Opcode::OP_DATA_1);
        compiler.add_opcode('OP_PUSHBYTES_2', Opcode::OP_DATA_2);
        compiler.add_opcode('OP_PUSHBYTES_3', Opcode::OP_DATA_3);
        compiler.add_opcode('OP_PUSHBYTES_4', Opcode::OP_DATA_4);
        compiler.add_opcode('OP_PUSHBYTES_5', Opcode::OP_DATA_5);
        compiler.add_opcode('OP_PUSHBYTES_6', Opcode::OP_DATA_6);
        compiler.add_opcode('OP_PUSHBYTES_7', Opcode::OP_DATA_7);
        compiler.add_opcode('OP_PUSHBYTES_8', Opcode::OP_DATA_8);
        compiler.add_opcode('OP_PUSHBYTES_9', Opcode::OP_DATA_9);
        compiler.add_opcode('OP_PUSHBYTES_10', Opcode::OP_DATA_10);
        compiler.add_opcode('OP_PUSHBYTES_11', Opcode::OP_DATA_11);
        compiler.add_opcode('OP_PUSHBYTES_12', Opcode::OP_DATA_12);
        compiler.add_opcode('OP_PUSHBYTES_13', Opcode::OP_DATA_13);
        compiler.add_opcode('OP_PUSHBYTES_14', Opcode::OP_DATA_14);
        compiler.add_opcode('OP_PUSHBYTES_15', Opcode::OP_DATA_15);
        compiler.add_opcode('OP_PUSHBYTES_16', Opcode::OP_DATA_16);
        compiler.add_opcode('OP_PUSHBYTES_17', Opcode::OP_DATA_17);
        compiler.add_opcode('OP_PUSHBYTES_18', Opcode::OP_DATA_18);
        compiler.add_opcode('OP_PUSHBYTES_19', Opcode::OP_DATA_19);
        compiler.add_opcode('OP_PUSHBYTES_20', Opcode::OP_DATA_20);
        compiler.add_opcode('OP_PUSHBYTES_21', Opcode::OP_DATA_21);
        compiler.add_opcode('OP_PUSHBYTES_22', Opcode::OP_DATA_22);
        compiler.add_opcode('OP_PUSHBYTES_23', Opcode::OP_DATA_23);
        compiler.add_opcode('OP_PUSHBYTES_24', Opcode::OP_DATA_24);
        compiler.add_opcode('OP_PUSHBYTES_25', Opcode::OP_DATA_25);
        compiler.add_opcode('OP_PUSHBYTES_26', Opcode::OP_DATA_26);
        compiler.add_opcode('OP_PUSHBYTES_27', Opcode::OP_DATA_27);
        compiler.add_opcode('OP_PUSHBYTES_28', Opcode::OP_DATA_28);
        compiler.add_opcode('OP_PUSHBYTES_29', Opcode::OP_DATA_29);
        compiler.add_opcode('OP_PUSHBYTES_30', Opcode::OP_DATA_30);
        compiler.add_opcode('OP_PUSHBYTES_31', Opcode::OP_DATA_31);
        compiler.add_opcode('OP_PUSHBYTES_32', Opcode::OP_DATA_32);
        compiler.add_opcode('OP_PUSHBYTES_33', Opcode::OP_DATA_33);
        compiler.add_opcode('OP_PUSHBYTES_34', Opcode::OP_DATA_34);
        compiler.add_opcode('OP_PUSHBYTES_35', Opcode::OP_DATA_35);
        compiler.add_opcode('OP_PUSHBYTES_36', Opcode::OP_DATA_36);
        compiler.add_opcode('OP_PUSHBYTES_37', Opcode::OP_DATA_37);
        compiler.add_opcode('OP_PUSHBYTES_38', Opcode::OP_DATA_38);
        compiler.add_opcode('OP_PUSHBYTES_39', Opcode::OP_DATA_39);
        compiler.add_opcode('OP_PUSHBYTES_40', Opcode::OP_DATA_40);
        compiler.add_opcode('OP_PUSHBYTES_41', Opcode::OP_DATA_41);
        compiler.add_opcode('OP_PUSHBYTES_42', Opcode::OP_DATA_42);
        compiler.add_opcode('OP_PUSHBYTES_43', Opcode::OP_DATA_43);
        compiler.add_opcode('OP_PUSHBYTES_44', Opcode::OP_DATA_44);
        compiler.add_opcode('OP_PUSHBYTES_45', Opcode::OP_DATA_45);
        compiler.add_opcode('OP_PUSHBYTES_46', Opcode::OP_DATA_46);
        compiler.add_opcode('OP_PUSHBYTES_47', Opcode::OP_DATA_47);
        compiler.add_opcode('OP_PUSHBYTES_48', Opcode::OP_DATA_48);
        compiler.add_opcode('OP_PUSHBYTES_49', Opcode::OP_DATA_49);
        compiler.add_opcode('OP_PUSHBYTES_50', Opcode::OP_DATA_50);
        compiler.add_opcode('OP_PUSHBYTES_51', Opcode::OP_DATA_51);
        compiler.add_opcode('OP_PUSHBYTES_52', Opcode::OP_DATA_52);
        compiler.add_opcode('OP_PUSHBYTES_53', Opcode::OP_DATA_53);
        compiler.add_opcode('OP_PUSHBYTES_54', Opcode::OP_DATA_54);
        compiler.add_opcode('OP_PUSHBYTES_55', Opcode::OP_DATA_55);
        compiler.add_opcode('OP_PUSHBYTES_56', Opcode::OP_DATA_56);
        compiler.add_opcode('OP_PUSHBYTES_57', Opcode::OP_DATA_57);
        compiler.add_opcode('OP_PUSHBYTES_58', Opcode::OP_DATA_58);
        compiler.add_opcode('OP_PUSHBYTES_59', Opcode::OP_DATA_59);
        compiler.add_opcode('OP_PUSHBYTES_60', Opcode::OP_DATA_60);
        compiler.add_opcode('OP_PUSHBYTES_61', Opcode::OP_DATA_61);
        compiler.add_opcode('OP_PUSHBYTES_62', Opcode::OP_DATA_62);
        compiler.add_opcode('OP_PUSHBYTES_63', Opcode::OP_DATA_63);
        compiler.add_opcode('OP_PUSHBYTES_64', Opcode::OP_DATA_64);
        compiler.add_opcode('OP_PUSHBYTES_65', Opcode::OP_DATA_65);
        compiler.add_opcode('OP_PUSHBYTES_66', Opcode::OP_DATA_66);
        compiler.add_opcode('OP_PUSHBYTES_67', Opcode::OP_DATA_67);
        compiler.add_opcode('OP_PUSHBYTES_68', Opcode::OP_DATA_68);
        compiler.add_opcode('OP_PUSHBYTES_69', Opcode::OP_DATA_69);
        compiler.add_opcode('OP_PUSHBYTES_70', Opcode::OP_DATA_70);
        compiler.add_opcode('OP_PUSHBYTES_71', Opcode::OP_DATA_71);
        compiler.add_opcode('OP_PUSHBYTES_72', Opcode::OP_DATA_72);
        compiler.add_opcode('OP_PUSHBYTES_73', Opcode::OP_DATA_73);
        compiler.add_opcode('OP_PUSHBYTES_74', Opcode::OP_DATA_74);
        compiler.add_opcode('OP_PUSHBYTES_75', Opcode::OP_DATA_75);
        compiler.add_opcode('OP_PUSHDATA1', Opcode::OP_PUSHDATA1);
        compiler.add_opcode('OP_PUSHDATA2', Opcode::OP_PUSHDATA2);
        compiler.add_opcode('OP_PUSHDATA4', Opcode::OP_PUSHDATA4);
        compiler.add_opcode('OP_1NEGATE', Opcode::OP_1NEGATE);
        compiler.add_opcode('OP_1', Opcode::OP_1);
        compiler.add_opcode('OP_TRUE', Opcode::OP_TRUE);
        compiler.add_opcode('OP_2', Opcode::OP_2);
        compiler.add_opcode('OP_3', Opcode::OP_3);
        compiler.add_opcode('OP_4', Opcode::OP_4);
        compiler.add_opcode('OP_5', Opcode::OP_5);
        compiler.add_opcode('OP_6', Opcode::OP_6);
        compiler.add_opcode('OP_7', Opcode::OP_7);
        compiler.add_opcode('OP_8', Opcode::OP_8);
        compiler.add_opcode('OP_9', Opcode::OP_9);
        compiler.add_opcode('OP_10', Opcode::OP_10);
        compiler.add_opcode('OP_11', Opcode::OP_11);
        compiler.add_opcode('OP_12', Opcode::OP_12);
        compiler.add_opcode('OP_13', Opcode::OP_13);
        compiler.add_opcode('OP_14', Opcode::OP_14);
        compiler.add_opcode('OP_15', Opcode::OP_15);
        compiler.add_opcode('OP_16', Opcode::OP_16);
        compiler.add_opcode('OP_PUSHNUM_NEG1', Opcode::OP_1NEGATE);
        compiler.add_opcode('OP_PUSHNUM_1', Opcode::OP_1);
        compiler.add_opcode('OP_PUSHNUM_2', Opcode::OP_2);
        compiler.add_opcode('OP_PUSHNUM_3', Opcode::OP_3);
        compiler.add_opcode('OP_PUSHNUM_4', Opcode::OP_4);
        compiler.add_opcode('OP_PUSHNUM_5', Opcode::OP_5);
        compiler.add_opcode('OP_PUSHNUM_6', Opcode::OP_6);
        compiler.add_opcode('OP_PUSHNUM_7', Opcode::OP_7);
        compiler.add_opcode('OP_PUSHNUM_8', Opcode::OP_8);
        compiler.add_opcode('OP_PUSHNUM_9', Opcode::OP_9);
        compiler.add_opcode('OP_PUSHNUM_10', Opcode::OP_10);
        compiler.add_opcode('OP_PUSHNUM_11', Opcode::OP_11);
        compiler.add_opcode('OP_PUSHNUM_12', Opcode::OP_12);
        compiler.add_opcode('OP_PUSHNUM_13', Opcode::OP_13);
        compiler.add_opcode('OP_PUSHNUM_14', Opcode::OP_14);
        compiler.add_opcode('OP_PUSHNUM_15', Opcode::OP_15);
        compiler.add_opcode('OP_PUSHNUM_16', Opcode::OP_16);
        compiler.add_opcode('OP_NOP', Opcode::OP_NOP);
        compiler.add_opcode('OP_IF', Opcode::OP_IF);
        compiler.add_opcode('OP_NOTIF', Opcode::OP_NOTIF);
        compiler.add_opcode('OP_VERIF', Opcode::OP_VERIF);
        compiler.add_opcode('OP_VERNOTIF', Opcode::OP_VERNOTIF);
        compiler.add_opcode('OP_ELSE', Opcode::OP_ELSE);
        compiler.add_opcode('OP_ENDIF', Opcode::OP_ENDIF);
        compiler.add_opcode('OP_VERIFY', Opcode::OP_VERIFY);
        compiler.add_opcode('OP_RETURN', Opcode::OP_RETURN);
        compiler.add_opcode('OP_TOALTSTACK', Opcode::OP_TOALTSTACK);
        compiler.add_opcode('OP_FROMALTSTACK', Opcode::OP_FROMALTSTACK);
        compiler.add_opcode('OP_2DROP', Opcode::OP_2DROP);
        compiler.add_opcode('OP_2DUP', Opcode::OP_2DUP);
        compiler.add_opcode('OP_3DUP', Opcode::OP_3DUP);
        compiler.add_opcode('OP_DROP', Opcode::OP_DROP);
        compiler.add_opcode('OP_DUP', Opcode::OP_DUP);
        compiler.add_opcode('OP_NIP', Opcode::OP_NIP);
        compiler.add_opcode('OP_PICK', Opcode::OP_PICK);
        compiler.add_opcode('OP_EQUAL', Opcode::OP_EQUAL);
        compiler.add_opcode('OP_EQUALVERIFY', Opcode::OP_EQUALVERIFY);
        compiler.add_opcode('OP_2ROT', Opcode::OP_2ROT);
        compiler.add_opcode('OP_2SWAP', Opcode::OP_2SWAP);
        compiler.add_opcode('OP_IFDUP', Opcode::OP_IFDUP);
        compiler.add_opcode('OP_DEPTH', Opcode::OP_DEPTH);
        compiler.add_opcode('OP_SIZE', Opcode::OP_SIZE);
        compiler.add_opcode('OP_ROT', Opcode::OP_ROT);
        compiler.add_opcode('OP_SWAP', Opcode::OP_SWAP);
        compiler.add_opcode('OP_1ADD', Opcode::OP_1ADD);
        compiler.add_opcode('OP_1SUB', Opcode::OP_1SUB);
        compiler.add_opcode('OP_NEGATE', Opcode::OP_NEGATE);
        compiler.add_opcode('OP_ABS', Opcode::OP_ABS);
        compiler.add_opcode('OP_NOT', Opcode::OP_NOT);
        compiler.add_opcode('OP_0NOTEQUAL', Opcode::OP_0NOTEQUAL);
        compiler.add_opcode('OP_ADD', Opcode::OP_ADD);
        compiler.add_opcode('OP_SUB', Opcode::OP_SUB);
        compiler.add_opcode('OP_BOOLAND', Opcode::OP_BOOLAND);
        compiler.add_opcode('OP_NUMEQUAL', Opcode::OP_NUMEQUAL);
        compiler.add_opcode('OP_NUMEQUALVERIFY', Opcode::OP_NUMEQUALVERIFY);
        compiler.add_opcode('OP_NUMNOTEQUAL', Opcode::OP_NUMNOTEQUAL);
        compiler.add_opcode('OP_LESSTHAN', Opcode::OP_LESSTHAN);
        compiler.add_opcode('OP_GREATERTHAN', Opcode::OP_GREATERTHAN);
        compiler.add_opcode('OP_LESSTHANOREQUAL', Opcode::OP_LESSTHANOREQUAL);
        compiler.add_opcode('OP_GREATERTHANOREQUAL', Opcode::OP_GREATERTHANOREQUAL);
        compiler.add_opcode('OP_MIN', Opcode::OP_MIN);
        compiler.add_opcode('OP_MAX', Opcode::OP_MAX);
        compiler.add_opcode('OP_WITHIN', Opcode::OP_WITHIN);
        compiler.add_opcode('OP_RIPEMD160', Opcode::OP_RIPEMD160);
        compiler.add_opcode('OP_SHA1', Opcode::OP_SHA1);
        compiler.add_opcode('OP_RESERVED', Opcode::OP_RESERVED);
        compiler.add_opcode('OP_RESERVED1', Opcode::OP_RESERVED1);
        compiler.add_opcode('OP_RESERVED2', Opcode::OP_RESERVED2);
        compiler.add_opcode('OP_VER', Opcode::OP_VER);
        compiler.add_opcode('OP_TUCK', Opcode::OP_TUCK);
        compiler.add_opcode('OP_BOOLOR', Opcode::OP_BOOLOR);
        compiler.add_opcode('OP_CAT', Opcode::OP_CAT);
        compiler.add_opcode('OP_SUBSTR', Opcode::OP_SUBSTR);
        compiler.add_opcode('OP_LEFT', Opcode::OP_LEFT);
        compiler.add_opcode('OP_RIGHT', Opcode::OP_RIGHT);
        compiler.add_opcode('OP_INVERT', Opcode::OP_INVERT);
        compiler.add_opcode('OP_AND', Opcode::OP_AND);
        compiler.add_opcode('OP_OR', Opcode::OP_OR);
        compiler.add_opcode('OP_XOR', Opcode::OP_XOR);
        compiler.add_opcode('OP_2MUL', Opcode::OP_2MUL);
        compiler.add_opcode('OP_2DIV', Opcode::OP_2DIV);
        compiler.add_opcode('OP_MUL', Opcode::OP_MUL);
        compiler.add_opcode('OP_DIV', Opcode::OP_DIV);
        compiler.add_opcode('OP_MOD', Opcode::OP_MOD);
        compiler.add_opcode('OP_LSHIFT', Opcode::OP_LSHIFT);
        compiler.add_opcode('OP_RSHIFT', Opcode::OP_RSHIFT);
        compiler.add_opcode('OP_NOP1', Opcode::OP_NOP1);
        compiler.add_opcode('OP_NOP2', Opcode::OP_NOP2);
        compiler.add_opcode('OP_NOP3', Opcode::OP_NOP3);
        compiler.add_opcode('OP_NOP4', Opcode::OP_NOP4);
        compiler.add_opcode('OP_NOP5', Opcode::OP_NOP5);
        compiler.add_opcode('OP_NOP6', Opcode::OP_NOP6);
        compiler.add_opcode('OP_NOP7', Opcode::OP_NOP7);
        compiler.add_opcode('OP_NOP8', Opcode::OP_NOP8);
        compiler.add_opcode('OP_NOP9', Opcode::OP_NOP9);
        compiler.add_opcode('OP_NOP10', Opcode::OP_NOP10);
        compiler.add_opcode('OP_ROLL', Opcode::OP_ROLL);
        compiler.add_opcode('OP_OVER', Opcode::OP_OVER);
        compiler.add_opcode('OP_2OVER', Opcode::OP_2OVER);
        compiler.add_opcode('OP_SHA256', Opcode::OP_SHA256);
        compiler.add_opcode('OP_HASH160', Opcode::OP_HASH160);
        compiler.add_opcode('OP_HASH256', Opcode::OP_HASH256);
        compiler.add_opcode('OP_CHECKSIG', Opcode::OP_CHECKSIG);
        compiler.add_opcode('OP_CHECKSIGVERIFY', Opcode::OP_CHECKSIGVERIFY);
        compiler.add_opcode('OP_CHECKMULTISIG', Opcode::OP_CHECKMULTISIG);
        compiler.add_opcode('OP_CHECKMULTISIGVERIFY', Opcode::OP_CHECKMULTISIGVERIFY);
        compiler.add_opcode('OP_CODESEPARATOR', Opcode::OP_CODESEPARATOR);
        compiler.add_opcode('OP_CHECKLOCKTIMEVERIFY', Opcode::OP_CHECKLOCKTIMEVERIFY);
        compiler.add_opcode('OP_CLTV', Opcode::OP_CHECKLOCKTIMEVERIFY);
        compiler.add_opcode('OP_CHECKSEQUENCEVERIFY', Opcode::OP_CHECKSEQUENCEVERIFY);
        compiler.add_opcode('OP_CSV', Opcode::OP_CHECKSEQUENCEVERIFY);

        compiler
    }

    fn add_opcode(ref self: Compiler, name: felt252, opcode: u8) {
        // Insert opcode formatted like OP_XXX
        self.opcodes.insert(name, NullableTrait::new(opcode));

        // Remove OP_ prefix and insert opcode XXX
        let nameu256 = name.into();
        let mut name_mask: u256 = 1;
        while name_mask < nameu256 {
            name_mask = name_mask * 256; // Shift left 1 byte
        };
        name_mask = name_mask / 16_777_216; // Shift right 3 bytes
        self.opcodes.insert((nameu256 % name_mask).try_into().unwrap(), NullableTrait::new(opcode));
    }

    fn compile(mut self: Compiler, script: ByteArray) -> Result<ByteArray, felt252> {
        let mut bytecode = "";
        let seperator = ' ';

        // Split the script into opcodes / data
        let mut split_script: Array<ByteArray> = array![];
        let mut current = "";
        let mut i = 0;
        let script_len = script.len();
        while i != script_len {
            let char = script[i].into();
            if char == seperator {
                if current == "" {
                    i += 1;
                    continue;
                }
                split_script.append(current);
                current = "";
            } else {
                current.append_byte(char);
            }
            i += 1;
        };
        // Handle the last opcode
        if current != "" {
            split_script.append(current);
        }

        // Compile the script into bytecode
        let mut i = 0;
        let script_len = split_script.len();
        let mut err = '';
        while i != script_len {
            let script_item = split_script.at(i);
            if is_hex(script_item) {
                ByteArrayTrait::append(ref bytecode, @hex_to_bytecode(script_item));
            } else if is_string(script_item) {
                ByteArrayTrait::append(ref bytecode, @string_to_bytecode(script_item));
            } else if is_number(script_item) {
                ByteArrayTrait::append(ref bytecode, @number_to_bytecode(script_item));
            } else {
                let opcode_nullable = self.opcodes.get(byte_array_to_felt252_be(script_item));
                if opcode_nullable.is_null() {
                    err = 'Compiler error: unknown opcode';
                    break;
                }
                bytecode.append_byte(opcode_nullable.deref());
            }
            i += 1;
        };
        if err != '' {
            return Result::Err(err);
        }
        Result::Ok(bytecode)
    }
}

// Remove the surrounding quotes and add the corrent append opcodes to the front
// https://github.com/btcsuite/btcd/blob/b161cd6a199b4e35acec66afc5aad221f05fe1e3/txs
// cript/scriptbuilder.go#L159
pub fn string_to_bytecode(script_item: @ByteArray) -> ByteArray {
    let mut bytecode = "";
    let mut i = 1;
    let word_len = script_item.len() - 2;
    let end = script_item.len() - 1;
    if word_len == 0 || (word_len == 1 && script_item[1] == 0) {
        bytecode.append_byte(Opcode::OP_0);
        return bytecode;
    } else if word_len == 1 && script_item[1] <= 16 {
        bytecode.append_byte(Opcode::OP_1 - 1 + script_item[1]);
        return bytecode;
    } else if word_len == 1 && script_item[1] == 0x81 {
        bytecode.append_byte(Opcode::OP_1NEGATE);
        return bytecode;
    }

    if word_len < Opcode::OP_PUSHDATA1.into() {
        bytecode.append_byte(Opcode::OP_DATA_1 - 1 + word_len.try_into().unwrap());
    } else if word_len < 0x100 {
        bytecode.append_byte(Opcode::OP_PUSHDATA1);
        bytecode.append_byte(word_len.try_into().unwrap());
    } else if word_len < 0x10000 {
        bytecode.append_byte(Opcode::OP_PUSHDATA2);
        // TODO: Little-endian?
        bytecode.append(@ScriptNum::wrap(word_len.into()));
    } else {
        bytecode.append_byte(Opcode::OP_PUSHDATA4);
        bytecode.append(@ScriptNum::wrap(word_len.into()));
    }
    while i != end {
        bytecode.append_byte(script_item[i]);
        i += 1;
    };
    bytecode
}

// Convert a number to bytecode
pub fn number_to_bytecode(script_item: @ByteArray) -> ByteArray {
    let mut bytecode = "";
    let mut i = 0;
    let script_item_len = script_item.len();
    let zero = '0';
    let negative = '-';
    let mut is_negative = false;
    if script_item[0] == negative {
        is_negative = true;
        i += 1;
    }
    let mut value: i64 = 0;
    while i != script_item_len {
        value = value * 10 + script_item[i].into() - zero;
        i += 1;
    };
    if is_negative {
        value = -value;
    }
    // TODO: Negative info lost before this
    if value == -1 {
        bytecode.append_byte(Opcode::OP_1NEGATE);
    } else if value > 0 && value <= 16 {
        bytecode.append_byte(Opcode::OP_1 - 1 + value.try_into().unwrap());
    } else if value == 0 {
        bytecode.append_byte(Opcode::OP_0);
    } else {
        // TODO: always script num?
        let script_num = ScriptNum::wrap(value);
        let script_num_len = script_num.len();
        if script_num_len < Opcode::OP_PUSHDATA1.into() {
            bytecode.append_byte(Opcode::OP_DATA_1 - 1 + script_num_len.try_into().unwrap());
        } else if script_num_len < 0x100 {
            bytecode.append_byte(Opcode::OP_PUSHDATA1);
            bytecode.append_byte(script_num_len.try_into().unwrap());
        }
        bytecode.append(@script_num);
    }
    bytecode
}
