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

pub fn min_le(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
	for i in (0..32).rev() {
		if a[i] > b[i] {
			return b;
		} else if b[i] > a[i] {
			return a;
		}
	}
	a
}

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

#[cfg(test)]
mod tests {
	use utils;

	fn hex_to_u256(hex: &str, out: &mut [u8; 32]) {
		assert_eq!(hex.len(), 64);

		let mut b = 0;
		let mut outpos = 0;
		for (idx, c) in hex.as_bytes().iter().enumerate() {
			b <<= 4;
			match *c {
				b'A'...b'F' => b |= c - b'A' + 10,
				b'a'...b'f' => b |= c - b'a' + 10,
				b'0'...b'9' => b |= c - b'0',
				_ => panic!("Bad hex"),
			}
			if (idx & 1) == 1 {
				out[outpos] = b;
				outpos += 1;
				b = 0;
			}
		}
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
