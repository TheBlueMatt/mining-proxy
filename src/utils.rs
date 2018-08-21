use std;

pub fn does_hash_meet_target(hash: &[u8], target: &[u8]) -> bool {
	assert_eq!(hash.len(), 32);
	assert_eq!(target.len(), 32);

	for i in (0..32).rev() {
		if hash[i] > target[i] {
			return false;
		} else if target[i] > hash[i] {
			return true;
		}
	}
	true
}

#[inline]
fn does_hash_meet_target_div(hash: &[u8], target: &[u8], shift: u8) -> bool {
	assert_eq!(hash.len(), 32);
	assert_eq!(target.len(), 32);

	for i in (0..32).rev() {
		if hash[i] > target[i] {
			let mut hashval = hash[i] as u16;
			let mut targetval = target[i] as u16;
			if i > 0 {
				hashval = ((hash[i - 1] as u16) << 8) | hashval;
				targetval = ((target[i - 1] as u16) << 8) | targetval;
			}
			return targetval > (hashval >> shift);
		} else if target[i] > hash[i] {
			return true;
		}
	}
	true
}

#[allow(dead_code)]
pub fn does_hash_meet_target_div2(hash: &[u8], target: &[u8]) -> bool {
	does_hash_meet_target_div(hash, target, 1)
}

pub fn does_hash_meet_target_div4(hash: &[u8], target: &[u8]) -> bool {
	does_hash_meet_target_div(hash, target, 2)
}

#[allow(dead_code)]
pub fn max_le(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
	for i in (0..32).rev() {
		if a[i] > b[i] {
			return a;
		} else if b[i] > a[i] {
			return b;
		}
	}
	a
}

/// Convert nbits to target returns: target([u8;32]), negative(bool), overflow(bool)
#[allow(dead_code)]
#[inline]
pub fn nbits_to_target(nbits: u32) -> ([u8; 32], bool, bool) {
	// Compact format: N = (-1^sign) * mantissa * 256^(exponent-3)
	let mut res = [0; 32];
	let mut negative = false;
	let mut overflow = false;
	let mut word;

	let nshift = (nbits >> 24) & 0xff;

	if nshift > 34 {
		overflow = true;
		return (res, negative, overflow);
	}

	// Fill three byte words
	for i in 0..3 {
		if nshift > i {
			word = ((nbits >> (8 * (2 - i))) & 0xff) as u8;
			if i == 0 {
				word &= 0x7f;
			}
			if nshift <= 32 + i {
				res[(nshift - i - 1) as usize] = word;
			} else if word > 0 {
				overflow = true;
			}
		}
	}

	negative = res != [0; 32] && nbits & 0x00800000 != 0;
	(res, negative, overflow)
}

/// Returns the highest value with the given number of leading 0s
#[allow(dead_code)]
#[inline]
pub fn leading_0s_to_target(zeros: u8) -> [u8; 32] {
	let mut res = [0xff; 32];
	for i in 0..zeros/8 {
		res[(31 - i) as usize] = 0;
	}
	if zeros & 7 != 0 {
		res[31 - (zeros/8) as usize] = 0xff >> (zeros & 7);
	}
	res
}

#[inline]
pub fn count_leading_zeros(target: &[u8]) -> u8 {
	assert_eq!(target.len(), 32);
	for i in 0..32 {
		if target[31 - i] != 0 {
			return 8*(i as u8) + (target[31 - i].leading_zeros() as u8);
		}
	}
	return 255;
}

#[allow(dead_code)]
pub const MILLION_DIFF_TARGET: [u8; 32] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x04, 0, 0, 0, 0, 0, 0];
#[allow(dead_code)]
#[inline]
pub fn target_to_diff_lb(target: &[u8; 32]) -> f64 {
	// We use a shitty approximation for a lower-bound on difficulty by simply calculating the
	// number of leading 0 bits in the target and applying a fudge factor...this will result in
	// up to 3/4 of shares failing, but that's OK.
	for i in 0..32 {
		if target[31 - i] != 0 {
			let exp = 8*((i as i32) - 4) + (target[31 - i].leading_zeros() as i32) - 1;
			assert!(exp >= std::f64::MIN_EXP);
			assert!(exp <= std::f64::MAX_EXP);
			return f64::from_bits(((exp + 1023) as u64) << 52);
		}
	}
	return std::f64::INFINITY;
}

#[inline]
pub fn le64_to_array(u: u64) -> [u8; 8] {
	let mut v = [0; 8];
	v[0] = ((u >> 8*0) & 0xff) as u8;
	v[1] = ((u >> 8*1) & 0xff) as u8;
	v[2] = ((u >> 8*2) & 0xff) as u8;
	v[3] = ((u >> 8*3) & 0xff) as u8;
	v[4] = ((u >> 8*4) & 0xff) as u8;
	v[5] = ((u >> 8*5) & 0xff) as u8;
	v[6] = ((u >> 8*6) & 0xff) as u8;
	v[7] = ((u >> 8*7) & 0xff) as u8;
	v
}

#[allow(dead_code)]
#[inline]
pub fn le32_to_array(u: u32) -> [u8; 4] {
	let mut v = [0; 4];
	v[0] = ((u >> 8*0) & 0xff) as u8;
	v[1] = ((u >> 8*1) & 0xff) as u8;
	v[2] = ((u >> 8*2) & 0xff) as u8;
	v[3] = ((u >> 8*3) & 0xff) as u8;
	v
}

#[inline]
pub fn slice_to_le16(v: &[u8]) -> u16 {
	((v[1] as u16) << 8*1) |
	((v[0] as u16) << 8*0)
}

#[inline]
pub fn slice_to_le32(v: &[u8]) -> u32 {
	((v[3] as u32) << 8*3) |
	((v[2] as u32) << 8*2) |
	((v[1] as u32) << 8*1) |
	((v[0] as u32) << 8*0)
}

#[inline]
pub fn slice_to_le64(v: &[u8]) -> u64 {
	((v[7] as u64) << 8*7) |
	((v[6] as u64) << 8*6) |
	((v[5] as u64) << 8*5) |
	((v[4] as u64) << 8*4) |
	((v[3] as u64) << 8*3) |
	((v[2] as u64) << 8*2) |
	((v[1] as u64) << 8*1) |
	((v[0] as u64) << 8*0)
}

pub fn push_bytes_hex(bytes: &[u8], out: &mut String) {
	for i in 0..bytes.len() {
		out.push(std::char::from_digit((bytes[i] >> 4) as u32, 16).unwrap());
		out.push(std::char::from_digit((bytes[i] & 0x0f) as u32, 16).unwrap());
	}
}

pub fn bytes_to_hex(bytes: &[u8]) -> String {
	let mut ret = String::with_capacity(bytes.len() * 2);
	push_bytes_hex(bytes, &mut ret);
	ret
}

#[derive(Debug)]
pub struct HandleError;
impl std::fmt::Display for HandleError {
	fn fmt(&self, fmt: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
		fmt.write_str("Failed to handle message")
	}
}
impl std::error::Error for HandleError {
	fn description(&self) -> &str {
		"Failed to handle message"
	}
}

#[allow(dead_code)]
pub fn hex_to_u256(hex: &str) -> Option<[u8; 32]> {
	if hex.len() != 64 { return None; }

	let mut out = [0; 32];

	let mut b = 0;
	let mut outpos = 0;
	for (idx, c) in hex.as_bytes().iter().enumerate() {
		b <<= 4;
		match *c {
			b'A'...b'F' => b |= c - b'A' + 10,
			b'a'...b'f' => b |= c - b'a' + 10,
			b'0'...b'9' => b |= c - b'0',
			_ => return None,
		}
		if (idx & 1) == 1 {
			out[outpos] = b;
			outpos += 1;
			b = 0;
		}
	}

	Some(out)
}

#[allow(dead_code)]
pub fn hex_to_u256_rev(hex: &str) -> Option<[u8; 32]> {
	if hex.len() != 64 { return None; }

	let mut out = [0; 32];

	let mut b = 0;
	let mut outpos = 32;
	for (idx, c) in hex.as_bytes().iter().enumerate() {
		b <<= 4;
		match *c {
			b'A'...b'F' => b |= c - b'A' + 10,
			b'a'...b'f' => b |= c - b'a' + 10,
			b'0'...b'9' => b |= c - b'0',
			_ => return None,
		}
		if (idx & 1) == 1 {
			outpos -= 1;
			out[outpos] = b;
			b = 0;
		}
	}

	Some(out)
}

#[cfg(test)]
mod tests {
	use utils;

	fn hex_to_u256(hex: &str, out: &mut [u8; 32]) {
		assert_eq!(hex.len(), 64);
		*out = utils::hex_to_u256(hex).unwrap();
	}

	#[test]
	fn test_1mill_target_lower_bound() {
		assert!(utils::target_to_diff_lb(&utils::MILLION_DIFF_TARGET) >= 1000000.0);
	}

	#[test]
	fn test_nbits_to_target() {
		assert_eq!(utils::nbits_to_target(0x172f4f7b), ([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 123, 79, 47, 0, 0, 0, 0, 0, 0, 0, 0, 0], false, false));
		assert_eq!(utils::nbits_to_target(0x002f4f7b), ([0; 32], false, false));
		assert_eq!(utils::nbits_to_target(0x012f4f7b), ([47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], false, false));
		assert_eq!(utils::nbits_to_target(0x022f4f7b), ([79, 47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], false, false));
		assert_eq!(utils::nbits_to_target(0x202f4f7b), ([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 123, 79, 47], false, false));
		assert_eq!(utils::nbits_to_target(0x212f4f7b), ([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 123, 79], false, true));
		assert_eq!(utils::nbits_to_target(0x2200007b), ([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 123], false, false));
		assert_eq!(utils::nbits_to_target(0x232f4f7b), ([0; 32], false, true));
		assert_eq!(utils::nbits_to_target(0x17af4f7b), ([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 123, 79, 47, 0, 0, 0, 0, 0, 0, 0, 0, 0], true, false));
	}

	#[test]
	fn test_target_lower_bound() {
		{
			let mut target = [0; 32];
			hex_to_u256("0000000000000000000000000000000000000000000000000000ffff00000000", &mut target);
			assert!(utils::target_to_diff_lb(&target) <= 1.0);
			assert!(utils::target_to_diff_lb(&target) >= 1.0 / 4.0);
		}

		{
			let mut target = [0; 32];
			hex_to_u256("0000000000000000000000000000000000000000a38955000000000000000000", &mut target);
			assert!(utils::target_to_diff_lb(&target) <= 3290605988755.001);
			assert!(utils::target_to_diff_lb(&target) >= 3290605988755.001 / 4.0);
		}

		{
			let mut target = [0; 32];
			hex_to_u256("ffffffffffffffffffffffffffffffffffffffffffffffffffff000000000000", &mut target);
			assert!(utils::target_to_diff_lb(&target) <= 65535.0);
			assert!(utils::target_to_diff_lb(&target) >= 65535.0 / 4.0);
		}

		{
			let mut target = [0; 32];
			hex_to_u256("ffffffffffffffffffffffffffffffffffffffffffffffffff00000000000000", &mut target);
			assert!(utils::target_to_diff_lb(&target) <= 16776960.0);
			assert!(utils::target_to_diff_lb(&target) >= 16776960.0 / 4.0);
		}

		{
			let mut target = [0; 32];
			hex_to_u256("ffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000", &mut target);
			assert!(utils::target_to_diff_lb(&target) <= 4294901760.0);
			assert!(utils::target_to_diff_lb(&target) >= 4294901760.0 / 4.0);
		}

		{
			let mut target = [0; 32];
			hex_to_u256("ffffffffffffffffffffffffffffffffffffffffffffff000000000000000000", &mut target);
			assert!(utils::target_to_diff_lb(&target) <= 1099494850560.0);
			assert!(utils::target_to_diff_lb(&target) >= 1099494850560.0 / 4.0);
		}

		{
			let mut target = [0; 32];
			hex_to_u256("ffffffffffffffffffffffffffffffffffffffffffff00000000000000000000", &mut target);
			assert!(utils::target_to_diff_lb(&target) <= 281470681743360.0);
			assert!(utils::target_to_diff_lb(&target) >= 281470681743360.0 / 4.0);
		}

		{
			let mut target = [0; 32];
			hex_to_u256("ffffffffffffffffffffffffffffffffffffffffff0000000000000000000000", &mut target);
			assert!(utils::target_to_diff_lb(&target) <= 72056494526300160.0);
			assert!(utils::target_to_diff_lb(&target) >= 72056494526300160.0 / 4.0);
		}

		{
			let mut target = [0; 32];
			hex_to_u256("ffffffffffffffffffffffffffffffffffffffff000000000000000000000000", &mut target);
			assert!(utils::target_to_diff_lb(&target) <= 18446462598732840000.0);
			assert!(utils::target_to_diff_lb(&target) >= 18446462598732840000.0 / 4.0);
		}

		{
			let mut target = [0; 32];
			hex_to_u256("0000000000000000000000000000000000000000010000000000000000000000", &mut target);
			assert!(utils::target_to_diff_lb(&target) <= 18446462598732840000.0);
			assert!(utils::target_to_diff_lb(&target) >= 18446462598732840000.0 / 4.0);
		}

		{
			let mut target = [0; 32];
			hex_to_u256("0000000000000000000000000000000000000000000100000000000000000000", &mut target);
			assert!(utils::target_to_diff_lb(&target) <= 72056494526300160.0);
			assert!(utils::target_to_diff_lb(&target) >= 72056494526300160.0 / 4.0);
		}

		{
			let mut target = [0; 32];
			hex_to_u256("0000000000000000000000000000000000000000000001000000000000000000", &mut target);
			assert!(utils::target_to_diff_lb(&target) <= 281470681743360.0);
			assert!(utils::target_to_diff_lb(&target) >= 281470681743360.0 / 4.0);
		}

		{
			let mut target = [0; 32];
			hex_to_u256("0000000000000000000000000000000000000000000000010000000000000000", &mut target);
			assert!(utils::target_to_diff_lb(&target) <= 1099494850560.0);
			assert!(utils::target_to_diff_lb(&target) >= 1099494850560.0 / 4.0);
		}

		{
			let mut target = [0; 32];
			hex_to_u256("0000000000000000000000000000000000000000000000000100000000000000", &mut target);
			assert!(utils::target_to_diff_lb(&target) <= 4294901760.0);
			assert!(utils::target_to_diff_lb(&target) >= 4294901760.0 / 4.0);
		}

		{
			let mut target = [0; 32];
			hex_to_u256("0000000000000000000000000000000000000000000000000001000000000000", &mut target);
			assert!(utils::target_to_diff_lb(&target) <= 16776960.0);
			assert!(utils::target_to_diff_lb(&target) >= 16776960.0 / 4.0);
		}

		{
			let mut target = [0; 32];
			hex_to_u256("0000000000000000000000000000000000000000000000000000010000000000", &mut target);
			assert!(utils::target_to_diff_lb(&target) <= 65535.0);
			assert!(utils::target_to_diff_lb(&target) >= 65535.0 / 4.0);
		}

		{
			let mut target = [0; 32];
			hex_to_u256("0000000000000000000000000000000000000000000000000000000100000000", &mut target);
			assert!(utils::target_to_diff_lb(&target) <= 255.99609375);
			assert!(utils::target_to_diff_lb(&target) >= 255.99609375 / 4.0);
		}

		{
			let mut target = [0; 32];
			hex_to_u256("0000000000000000000000000000000000000000000000000000000001000000", &mut target);
			assert!(utils::target_to_diff_lb(&target) <= 0.9999847412109375);
			assert!(utils::target_to_diff_lb(&target) >= 0.9999847412109375 / 4.0);
		}

		{
			let mut target = [0; 32];
			hex_to_u256("0000000000000000000000000000000000000000000000000000000000010000", &mut target);
			assert!(utils::target_to_diff_lb(&target) <= 0.0039061903953552246);
			assert!(utils::target_to_diff_lb(&target) >= 0.0039061903953552246 / 4.0);
		}

		{
			let mut target = [0; 32];
			hex_to_u256("0000000000000000000000000000000000000000000000000000000000000100", &mut target);
			assert!(utils::target_to_diff_lb(&target) <= 1.5258556231856346e-05);
			assert!(utils::target_to_diff_lb(&target) >= 1.5258556231856346e-05 / 4.0);
		}

		{
			let mut target = [0; 32];
			hex_to_u256("0000000000000000000000000000000000000000000000000000000000000001", &mut target);
			assert!(utils::target_to_diff_lb(&target) <= 5.960373528068885e-08);
			assert!(utils::target_to_diff_lb(&target) >= 5.960373528068885e-08 / 4.0);
		}

		{
			let mut target = [0; 32];
			hex_to_u256("00000000000000000000000000000000000000000000000000000000000000e0", &mut target);
			assert!(utils::target_to_diff_lb(&target) <= 2.6608810393164665e-10);
			assert!(utils::target_to_diff_lb(&target) >= 2.6608810393164665e-10 / 4.0);
		}

		{
			let mut target = [0; 32];
			hex_to_u256("000000000000000000000000000000000000000000000000ffffff0000000000", &mut target);
			assert!(utils::target_to_diff_lb(&target) <= 255.99610900855714);
			assert!(utils::target_to_diff_lb(&target) >= 255.99610900855714 / 4.0);
		}

		{
			let mut target = [0; 32];
			hex_to_u256("0000000000000000000000000000000000000000000000ffffff000000000000", &mut target);
			assert!(utils::target_to_diff_lb(&target) <= 65535.00390619063);
			assert!(utils::target_to_diff_lb(&target) >= 65535.00390619063 / 4.0);
		}
	}
}
