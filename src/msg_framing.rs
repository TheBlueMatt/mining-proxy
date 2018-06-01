use bitcoin::blockdata::transaction::{TxOut,Transaction};
use bitcoin::blockdata::script::Script;
use bitcoin::util::hash::Sha256dHash;
use bitcoin::network;

use bytes;
use bytes::BufMut;

use futures::sync::mpsc;

use tokio_io::codec;

use secp256k1::key::PublicKey;
use secp256k1::Secp256k1;
use secp256k1::Signature;

use std::error::Error;
use std::{cmp, fmt, io};
use std::sync::Arc;

fn le16_into_slice(u: u16, v: &mut [u8]) {
	assert_eq!(v.len(), 2);
	v[0] = ((u >> 8*0) & 0xff) as u8;
	v[1] = ((u >> 8*1) & 0xff) as u8;
}

fn le24_into_slice(u: usize, v: &mut [u8]) -> bool {
	if u > 0xffffff { return false; }
	assert_eq!(v.len(), 3);
	v[0] = ((u >> 8*0) & 0xff) as u8;
	v[1] = ((u >> 8*1) & 0xff) as u8;
	v[2] = ((u >> 8*2) & 0xff) as u8;
	true
}

fn push_compact_size(u: usize, v: &mut bytes::BytesMut) {
	match u {
		0...253 => {
			v.reserve(1);
			v.put_u8(u as u8);
		},
		253...0x10000 => {
			v.reserve(3);
			v.put_u8(253);
			v.put_u16_le(u as u16);
		},
		_ => {
			v.reserve(5);
			v.put_u8(254);
			v.put_u32_le(u as u32);
		},
	}
}

#[derive(Clone)]
pub struct BlockTemplate {
	pub template_timestamp: u64,
	pub target: [u8; 32],

	pub header_version: u32,
	pub header_prevblock: [u8; 32],
	pub header_time: u32,
	pub header_nbits: u32,

	pub merkle_rhss: Vec<[u8; 32]>,
	pub coinbase_value_remaining: u64,

	pub coinbase_version: u32,
	pub coinbase_prefix: Vec<u8>,
	pub coinbase_postfix: Vec<u8>,
	pub coinbase_input_sequence: u32,
	pub appended_coinbase_outputs: Vec<TxOut>,
	pub coinbase_locktime: u32,
}
impl BlockTemplate {
	pub fn encode_unsigned(&self, res: &mut bytes::BytesMut) {
		res.reserve(650); // Round upper bound assuming 1, 33-byte-sPK output
		res.put_u64_le(self.template_timestamp);
		res.put_slice(&self.target);

		res.put_u32_le(self.header_version);
		res.put_slice(&self.header_prevblock);
		res.put_u32_le(self.header_time);
		res.put_u32_le(self.header_nbits);

		res.put_u8(self.merkle_rhss.len() as u8);
		for merkle_rhs in self.merkle_rhss.iter() {
			res.put_slice(merkle_rhs);
		}
		res.put_u64_le(self.coinbase_value_remaining);

		res.put_u32_le(self.coinbase_version);
		res.put_u8(self.coinbase_prefix.len() as u8);
		res.put_slice(&self.coinbase_prefix[..]);
		res.put_u8(self.coinbase_postfix.len() as u8);
		res.put_slice(&self.coinbase_postfix[..]);
		res.put_u32_le(self.coinbase_input_sequence);

		res.put_u16_le(0);
		let remaining_len_pos = res.len();

		push_compact_size(self.appended_coinbase_outputs.len(), res);
		for txout in self.appended_coinbase_outputs.iter() {
			res.reserve(8 + 5 + txout.script_pubkey.len() + 4);
			res.put_u64_le(txout.value);
			push_compact_size(txout.script_pubkey.len(), res);
			res.put_slice(&txout.script_pubkey[..]);
		}
		res.put_u32_le(self.coinbase_locktime);

		le16_into_slice((res.len() - remaining_len_pos) as u16, &mut res[remaining_len_pos - 2..remaining_len_pos]);
	}
}

#[derive(Clone)]
pub struct CoinbasePrefixPostfix {
	pub timestamp: u64,
	pub coinbase_prefix_postfix: Vec<u8>,
}
impl CoinbasePrefixPostfix {
	pub fn encode_unsigned(&self, res: &mut bytes::BytesMut) {
		res.reserve(8 + 1 + self.coinbase_prefix_postfix.len());
		res.put_u64_le(self.timestamp);
		res.put_u8(self.coinbase_prefix_postfix.len() as u8);
		res.put_slice(&self.coinbase_prefix_postfix[..]);
	}
}

#[derive(Clone)]
pub struct WinningNonce {
	pub template_timestamp: u64,
	pub header_version: u32,
	pub header_time: u32,
	pub header_nonce: u32,
	pub user_tag: Vec<u8>,
	pub coinbase_tx: Transaction,
}
impl WinningNonce {
	pub fn encode(&self, res: &mut bytes::BytesMut) {
		let tx_enc = network::serialize::serialize(&self.coinbase_tx).unwrap();
		res.reserve(8 + 4*4 + tx_enc.len() + 1 + self.user_tag.len());
		res.put_u64_le(self.template_timestamp);
		res.put_u32_le(self.header_version);
		res.put_u32_le(self.header_time);
		res.put_u32_le(self.header_nonce);
		res.put_u8(self.user_tag.len() as u8);
		res.put_slice(&self.user_tag[..]);
		res.put_u32_le(tx_enc.len() as u32);
		res.put_slice(&tx_enc[..]);
	}
}

pub struct TransactionData {
	pub template_timestamp: u64,
	pub transactions: Vec<Transaction>,
}
impl TransactionData {
	pub fn encode_unsigned(&self, res: &mut bytes::BytesMut) {
		res.reserve(8+4);
		res.put_u64_le(self.template_timestamp);
		res.put_u32_le(self.transactions.len() as u32);
		for tx in self.transactions.iter() {
			let tx_enc = network::serialize::serialize(tx).unwrap();
			res.reserve(4 + tx_enc.len());
			res.put_u32_le(tx_enc.len() as u32);
			res.put_slice(&tx_enc[..]);
		}
	}
}

#[derive(Clone)]
pub struct BlockTemplateHeader {
	pub template_timestamp: u64,
	pub template_variant: u64,
	pub target: [u8; 32],

	pub header_version: u32,
	pub header_prevblock: [u8; 32],
	pub header_merkle_root: [u8; 32],
	pub header_time: u32,
	pub header_nbits: u32,
}
impl BlockTemplateHeader {
	pub fn encode_unsigned(&self, res: &mut bytes::BytesMut) {
		res.reserve(124);
		res.put_u64_le(self.template_timestamp);
		res.put_u64_le(self.template_variant);
		res.put_slice(&self.target);

		res.put_u32_le(self.header_version);
		res.put_slice(&self.header_prevblock);
		res.put_slice(&self.header_merkle_root);
		res.put_u32_le(self.header_time);
		res.put_u32_le(self.header_nbits);
	}
}

#[derive(Clone)]
pub struct WorkInfo {
	pub template: Arc<BlockTemplate>,
	pub solutions: mpsc::UnboundedSender<Arc<(WinningNonce, Sha256dHash)>>,
}

pub enum WorkMessage {
	ProtocolSupport {
		max_version: u16,
		min_version: u16,
		flags: u16,
	},
	ProtocolVersion {
		selected_version: u16,
		flags: u16,
		auth_key: PublicKey,
	},
	BlockTemplate {
		signature: Signature,
		template: BlockTemplate,
	},
	WinningNonce {
		nonces: WinningNonce,
	},
	TransactionDataRequest {
		template_timestamp: u64,
	},
	TransactionData {
		signature: Signature,
		data: TransactionData,
	},
	CoinbasePrefixPostfix {
		signature: Signature,
		coinbase_prefix_postfix: CoinbasePrefixPostfix,
	},
	BlockTemplateHeader {
		signature: Signature,
		template: BlockTemplateHeader,
	},
	WinningNonceHeader {
		template_timestamp: u64,
		template_variant: u64,
		header_version: u32,
		header_time: u32,
		header_nonce: u32,
		user_tag: Vec<u8>,
	},
	NewWorkServer {
		signature: Signature,
		new_host_port: String,
	},
	VendorMessage {
		signature: Option<Signature>,
		vendor: Vec<u8>,
		message: Vec<u8>,
	},
}

/// Decoder for work messages, not that we simply skip decoding Vendor messages to avoid creating a
/// 16MB read buffer for them.
pub struct WorkMsgFramer {
	secp_ctx: Secp256k1,
	/// Used to avoid reading large useless vendor messages into memory
	skip_bytes: usize,
}

impl WorkMsgFramer {
	pub fn new() -> WorkMsgFramer {
		WorkMsgFramer {
			secp_ctx: Secp256k1::new(),
			skip_bytes: 0,
		}
	}
}

#[derive(Debug)]
struct CodecError;
impl fmt::Display for CodecError {
	fn fmt(&self, fmt: &mut fmt::Formatter) -> Result<(), fmt::Error> {
		fmt.write_str("Bad data")
	}
}
impl Error for CodecError {
	fn description(&self) -> &str {
		"Bad data"
	}
}

impl codec::Encoder for WorkMsgFramer {
	type Item = WorkMessage;
	type Error = io::Error;

	fn encode(&mut self, msg: WorkMessage, res: &mut bytes::BytesMut) -> Result<(), io::Error> {
		match msg {
			WorkMessage::ProtocolSupport { max_version, min_version, flags } => {
				res.reserve(1 + 3 + 2*3);
				res.put_u8(1);
				res.put_u8(0x06);
				res.put_u16_le(0);
				res.put_u16_le(max_version);
				res.put_u16_le(min_version);
				res.put_u16_le(flags);
			},
			WorkMessage::ProtocolVersion { selected_version, flags, ref auth_key } => {
				res.reserve(1 + 3 + 2 + 33);
				res.put_u8(2);
				res.put_u8(0x25);
				res.put_u16_le(0);
				res.put_u16_le(selected_version);
				res.put_u16_le(flags);
				res.put_slice(&auth_key.serialize());
			},
			WorkMessage::BlockTemplate { ref signature, ref template } => {
				res.reserve(1 + 3 + 33);
				res.put_u8(3);

				let len_pos = res.len();
				res.put_u8(0);
				res.put_u16_le(0);

				res.put_slice(&signature.serialize_compact(&self.secp_ctx));
				template.encode_unsigned(res);

				if !le24_into_slice(res.len() - len_pos - 3, &mut res[len_pos..len_pos + 3]) {
					return Err(io::Error::new(io::ErrorKind::InvalidData, CodecError))
				}
			},
			WorkMessage::WinningNonce { ref nonces } => {
				res.reserve(1 + 3);
				res.put_u8(4);

				let len_pos = res.len();
				res.put_u8(0);
				res.put_u16_le(0);

				nonces.encode(res);

				if !le24_into_slice(res.len() - len_pos - 3, &mut res[len_pos..len_pos + 3]) {
					return Err(io::Error::new(io::ErrorKind::InvalidData, CodecError))
				}
			},
			WorkMessage::TransactionDataRequest { template_timestamp } => {
				res.reserve(1 + 3 + 8);
				res.put_u8(5);
				res.put_u8(8);
				res.put_u16_le(0);
				res.put_u64_le(template_timestamp);
			}
			WorkMessage::TransactionData { ref signature, ref data } => {
				res.reserve(1 + 3 + 33);
				res.put_u8(6);

				let len_pos = res.len();
				res.put_u8(0);
				res.put_u16_le(0);

				res.put_slice(&signature.serialize_compact(&self.secp_ctx));
				data.encode_unsigned(res);

				if !le24_into_slice(res.len() - len_pos - 3, &mut res[len_pos..len_pos + 3]) {
					return Err(io::Error::new(io::ErrorKind::InvalidData, CodecError))
				}
			},
			WorkMessage::CoinbasePrefixPostfix { ref signature, ref coinbase_prefix_postfix } => {
				res.reserve(1 + 3 + 33);
				res.put_u8(7);

				let len_pos = res.len();
				res.put_u8(0);
				res.put_u16_le(0);

				res.put_slice(&signature.serialize_compact(&self.secp_ctx));
				coinbase_prefix_postfix.encode_unsigned(res);

				if !le24_into_slice(res.len() - len_pos - 3, &mut res[len_pos..len_pos + 3]) {
					return Err(io::Error::new(io::ErrorKind::InvalidData, CodecError))
				}
			},
			WorkMessage::BlockTemplateHeader { ref signature, ref template } => {
				res.reserve(1 + 3 + 33);
				res.put_u8(8);

				let len_pos = res.len();
				res.put_u8(0);
				res.put_u16_le(0);

				res.put_slice(&signature.serialize_compact(&self.secp_ctx));
				template.encode_unsigned(res);

				if !le24_into_slice(res.len() - len_pos - 3, &mut res[len_pos..len_pos + 3]) {
					return Err(io::Error::new(io::ErrorKind::InvalidData, CodecError))
				}
			},
			WorkMessage::WinningNonceHeader { template_timestamp, template_variant, header_version, header_time, header_nonce, ref user_tag } => {
				res.reserve(33 + user_tag.len());
				res.put_u8(9);
				res.put_u16_le(29 + user_tag.len() as u16);
				res.put_u8(0);
				res.put_u64_le(template_timestamp);
				res.put_u64_le(template_variant);
				res.put_u32_le(header_version);
				res.put_u32_le(header_time);
				res.put_u32_le(header_nonce);
				res.put_u8(user_tag.len() as u8);
				res.put_slice(&user_tag[..]);
			},
			WorkMessage::NewWorkServer { ref signature, ref new_host_port } => {
				res.reserve(1 + 3 + 33 + 1 + new_host_port.len());
				res.put_u8(10);
				res.put_u16_le(33 + 1 + new_host_port.len() as u16);
				res.put_u8(0);
				res.put_slice(&signature.serialize_compact(&self.secp_ctx));
				res.put_u8(new_host_port.len() as u8);
				res.put_slice(new_host_port.as_bytes());
			},
			WorkMessage::VendorMessage { ref signature, ref vendor, ref message } => {
				let len = 1 + if signature.is_some() { 33 } else { 0 } + 1 + vendor.len() + message.len();
				if len > 0xffffff {
					return Err(io::Error::new(io::ErrorKind::InvalidData, CodecError));
				}

				res.reserve(1 + 3 + len);
				res.put_u8(11);
				res.put_u8(((len >> 8*0) & 0xff) as u8);
				res.put_u8(((len >> 8*1) & 0xff) as u8);
				res.put_u8(((len >> 8*2) & 0xff) as u8);

				match signature {
					&Some(ref sig) => {
						res.put_u8(1);
						res.put_slice(&sig.serialize_compact(&self.secp_ctx));
					},
					&None => res.put_u8(0),
				}

				res.put_u8(vendor.len() as u8);
				res.put_slice(&vendor);
				res.put_slice(&message);
			},
		}
		Ok(())
	}
}

#[inline]
fn slice_to_le16(v: &[u8]) -> u16 {
	((v[1] as u16) << 8*1) |
	((v[0] as u16) << 8*0)
}

#[inline]
fn slice_to_le32(v: &[u8]) -> u32 {
	((v[3] as u32) << 8*3) |
	((v[2] as u32) << 8*2) |
	((v[1] as u32) << 8*1) |
	((v[0] as u32) << 8*0)
}

#[inline]
fn slice_to_le64(v: &[u8]) -> u64 {
	((v[7] as u64) << 8*7) |
	((v[6] as u64) << 8*6) |
	((v[5] as u64) << 8*5) |
	((v[4] as u64) << 8*4) |
	((v[3] as u64) << 8*3) |
	((v[2] as u64) << 8*2) |
	((v[1] as u64) << 8*1) |
	((v[0] as u64) << 8*0)
}

impl codec::Decoder for WorkMsgFramer {
	type Item = WorkMessage;
	type Error = io::Error;

	fn decode(&mut self, bytes: &mut bytes::BytesMut) -> Result<Option<WorkMessage>, io::Error> {
		if self.skip_bytes != 0 {
			let read = cmp::min(self.skip_bytes, bytes.len());
			bytes.advance(read);
			self.skip_bytes -= read;
			if self.skip_bytes != 0 { return Ok(None); }
		}

		if bytes.len() < 4 { return Ok(None); }

		let len = ((((bytes[3] as usize) << 8) | (bytes[2] as usize)) << 8) | bytes[1] as usize;

		if match bytes[0] {
			1 => len != 6,
			2 => len != 37,
			3 => len > 1000202,
			4 => len > 1000280,
			5 => len != 8,
			6 => len > 4000076,
			7 => len > 169,
			8 => len > 188,
			9 => len > 284,
			10 => len > 320,
			11 => false,
			_ => true,
		} {
			return Err(io::Error::new(io::ErrorKind::InvalidData, CodecError));
		}

		if bytes[0] == 11 { // Vendor message
			if bytes.len() >= 4 + len {
				bytes.advance(4 + len);
				return Ok(None);
			}
			self.skip_bytes = len + 4 - bytes.len();
			let skip = bytes.len();
			bytes.advance(skip);
			return Ok(None);
		}

		if bytes.len() < 4 + len { return Ok(None); }

		let mut read_pos = 4;
		macro_rules! get_slice {
			( $size: expr ) => {
				{
					if read_pos as u64 + $size as u64 > len as u64 + 4 {
						return Err(io::Error::new(io::ErrorKind::InvalidData, CodecError));
					}
					read_pos += $size as usize;
					&bytes[read_pos - ($size as usize)..read_pos]
				}
			}
		}
		macro_rules! advance_bytes {
			() => {
				{
					if read_pos != len + 4 {
						return Err(io::Error::new(io::ErrorKind::InvalidData, CodecError));
					}
					bytes.advance(read_pos);
				}
			}
		}

		match bytes[0] {
			1 => {
				let msg = WorkMessage::ProtocolSupport {
					max_version: slice_to_le16(get_slice!(2)),
					min_version: slice_to_le16(get_slice!(2)),
					flags: slice_to_le16(get_slice!(2)),
				};
				advance_bytes!();
				Ok(Some(msg))
			},
			2 => {
				let selected_version = slice_to_le16(get_slice!(2));
				if selected_version != 1 {
					// We don't know how to deserialize anything else...
					return Err(io::Error::new(io::ErrorKind::InvalidData, CodecError))
				}
				let msg = WorkMessage::ProtocolVersion {
					selected_version: selected_version,
					flags: slice_to_le16(get_slice!(2)),
					auth_key: match PublicKey::from_slice(&self.secp_ctx, get_slice!(33)) {
						Ok(key) => key,
						Err(_) => {
							return Err(io::Error::new(io::ErrorKind::InvalidData, CodecError))
						}
					}
				};
				advance_bytes!();
				Ok(Some(msg))
			},
			3 => {
				// Quick check to make sure we dont try to fill in a struct partially
				if bytes.len() < 64+8+32+4+32+4+4+1+8+4+1+4+1+4 {
					return Ok(None);
				}

				let signature = match Signature::from_compact(&self.secp_ctx, get_slice!(64)) {
					Ok(sig) => sig,
					Err(_) => return Err(io::Error::new(io::ErrorKind::InvalidData, CodecError))
				};
				let template_timestamp = slice_to_le64(get_slice!(8));
				let mut target = [0; 32];
				target[..].copy_from_slice(get_slice!(32));

				let header_version = slice_to_le32(get_slice!(4));
				let mut header_prevblock = [0; 32];
				header_prevblock[..].copy_from_slice(get_slice!(32));
				let header_time = slice_to_le32(get_slice!(4));
				let header_nbits = slice_to_le32(get_slice!(4));

				let merkle_rhss_count = get_slice!(1)[0] as usize;
				if merkle_rhss_count > 16 {
					return Err(io::Error::new(io::ErrorKind::InvalidData, CodecError))
				}
				let mut merkle_rhss = Vec::with_capacity(merkle_rhss_count);
				for _ in 0..merkle_rhss_count {
					let mut merkle_rhs = [0; 32];
					merkle_rhs[..].copy_from_slice(get_slice!(32));
					merkle_rhss.push(merkle_rhs);
				}

				let coinbase_value_remaining = slice_to_le64(get_slice!(8));

				let coinbase_version = slice_to_le32(get_slice!(4));
				let coinbase_prefix_len = get_slice!(1)[0] as usize;
				if coinbase_prefix_len > 92 {
					return Err(io::Error::new(io::ErrorKind::InvalidData, CodecError))
				}
				let coinbase_prefix = get_slice!(coinbase_prefix_len).to_vec();

				let coinbase_postfix_len = get_slice!(1)[0] as usize;
				if coinbase_postfix_len > 92 || coinbase_prefix_len + coinbase_postfix_len > 92 {
					return Err(io::Error::new(io::ErrorKind::InvalidData, CodecError))
				}
				let coinbase_postfix = get_slice!(coinbase_postfix_len).to_vec();

				let coinbase_input_sequence = slice_to_le32(get_slice!(4));

				let remaining_coinbase_tx_len = slice_to_le16(get_slice!(2));
				if remaining_coinbase_tx_len > 32767 {
					return Err(io::Error::new(io::ErrorKind::InvalidData, CodecError))
				}
				let mut coinbase_sketch_data = vec!(0, 0, 0, 0, 0, 1, 0);
				coinbase_sketch_data.extend_from_slice(get_slice!(remaining_coinbase_tx_len));
				let coinbase_sketch: Transaction = match network::serialize::deserialize(&coinbase_sketch_data[..]) {
					Ok(tx) => tx,
					Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e)),
				};

				let msg = WorkMessage::BlockTemplate {
					signature: signature,
					template: BlockTemplate {
						template_timestamp,
						target,

						header_version,
						header_prevblock,
						header_time,
						header_nbits,

						merkle_rhss,
						coinbase_value_remaining,

						coinbase_version,
						coinbase_prefix,
						coinbase_postfix,
						coinbase_input_sequence,
						appended_coinbase_outputs: coinbase_sketch.output,
						coinbase_locktime: coinbase_sketch.lock_time,
					}
				};
				advance_bytes!();
				Ok(Some(msg))
			},
			4 => {
				let template_timestamp = slice_to_le64(get_slice!(8));
				let header_version = slice_to_le32(get_slice!(4));
				let header_time = slice_to_le32(get_slice!(4));
				let header_nonce = slice_to_le32(get_slice!(4));
				let user_tag = get_slice!(get_slice!(1)[0]).to_vec();
				let tx_len = slice_to_le32(get_slice!(4));
				if tx_len > 1000000 {
					return Err(io::Error::new(io::ErrorKind::InvalidData, CodecError))
				}
				let coinbase_tx = match network::serialize::deserialize(get_slice!(tx_len)) {
					Ok(tx) => tx,
					Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e))
				};
				let msg = WorkMessage::WinningNonce {
					nonces: WinningNonce {
						template_timestamp,
						header_version,
						header_time,
						header_nonce,
						user_tag,
						coinbase_tx,
					}
				};
				advance_bytes!();
				Ok(Some(msg))
			},
			5 => {
				let msg = WorkMessage::TransactionDataRequest {
					template_timestamp: slice_to_le64(get_slice!(8)),
				};
				advance_bytes!();
				Ok(Some(msg))
			},
			6 => {
				let signature = match Signature::from_compact(&self.secp_ctx, get_slice!(64)) {
					Ok(sig) => sig,
					Err(_) => return Err(io::Error::new(io::ErrorKind::InvalidData, CodecError))
				};
				let template_timestamp = slice_to_le64(get_slice!(8));

				let tx_count = slice_to_le32(get_slice!(4)) as usize;
				if bytes.len() < 64 + 8 + 4 + tx_count * 4 {
					return Ok(None)
				}
				let mut txn = Vec::with_capacity(tx_count);
				for _ in 0..tx_count {
					let tx_len = slice_to_le32(get_slice!(4));
					let tx_data = match network::serialize::deserialize(get_slice!(tx_len)) {
						Ok(tx) => tx,
						Err(_) => return Err(io::Error::new(io::ErrorKind::InvalidData, CodecError))
					};
					txn.push(tx_data);
				}

				let msg = WorkMessage::TransactionData {
					signature: signature,
					data: TransactionData {
						template_timestamp,
						transactions: txn,
					},
				};
				advance_bytes!();
				Ok(Some(msg))
			},
			7 => {
				let signature = match Signature::from_compact(&self.secp_ctx, get_slice!(64)) {
					Ok(sig) => sig,
					Err(_) => return Err(io::Error::new(io::ErrorKind::InvalidData, CodecError))
				};
				let timestamp = slice_to_le64(get_slice!(8));
				let prefix_postfix_len = get_slice!(1)[0];
				if prefix_postfix_len > 100 {
					return Err(io::Error::new(io::ErrorKind::InvalidData, CodecError))
				}
				let msg = WorkMessage::CoinbasePrefixPostfix {
					signature: signature,
					coinbase_prefix_postfix: CoinbasePrefixPostfix {
						timestamp: timestamp,
						coinbase_prefix_postfix: get_slice!(prefix_postfix_len).to_vec(),
					}
				};
				advance_bytes!();
				Ok(Some(msg))
			},
			8 => {
				let signature = match Signature::from_compact(&self.secp_ctx, get_slice!(64)) {
					Ok(sig) => sig,
					Err(_) => return Err(io::Error::new(io::ErrorKind::InvalidData, CodecError))
				};
				let template_timestamp = slice_to_le64(get_slice!(8));
				let template_variant = slice_to_le64(get_slice!(8));

				let mut target = [0; 32];
				target[..].copy_from_slice(get_slice!(32));

				let header_version = slice_to_le32(get_slice!(4));
				let mut header_prevblock = [0; 32];
				header_prevblock[..].copy_from_slice(get_slice!(32));
				let mut header_merkle_root = [0; 32];
				header_merkle_root[..].copy_from_slice(get_slice!(32));

				let msg = WorkMessage::BlockTemplateHeader {
					signature: signature,
					template: BlockTemplateHeader {
						template_timestamp,
						template_variant: template_variant,
						target: target,

						header_version: header_version,
						header_prevblock: header_prevblock,
						header_merkle_root: header_merkle_root,
						header_time: slice_to_le32(get_slice!(4)),
						header_nbits: slice_to_le32(get_slice!(4)),
					},
				};
				advance_bytes!();
				Ok(Some(msg))
			},
			9 => {
				let msg = WorkMessage::WinningNonceHeader {
					template_timestamp: slice_to_le64(get_slice!(8)),
					template_variant: slice_to_le64(get_slice!(8)),

					header_version: slice_to_le32(get_slice!(4)),
					header_time: slice_to_le32(get_slice!(4)),
					header_nonce: slice_to_le32(get_slice!(4)),

					user_tag: get_slice!(get_slice!(1)[0]).to_vec(),
				};
				advance_bytes!();
				Ok(Some(msg))
			},
			10 => {
				let signature = match Signature::from_compact(&self.secp_ctx, get_slice!(64)) {
					Ok(sig) => sig,
					Err(_) => return Err(io::Error::new(io::ErrorKind::InvalidData, CodecError))
				};
				let new_host_port = match String::from_utf8(get_slice!(get_slice!(1)[0]).to_vec()) {
					Ok(string) => string,
					Err(_) => return Err(io::Error::new(io::ErrorKind::InvalidData, CodecError))
				};
				let msg = WorkMessage::NewWorkServer {
					signature,
					new_host_port,
				};
				advance_bytes!();
				Ok(Some(msg))
			},
			// 11 (VendorMessage) handled pre-match
			_ => {
				return Err(io::Error::new(io::ErrorKind::InvalidData, CodecError))
			}
		}
	}
}

#[derive(Clone)]
pub struct PoolPayoutInfo {
	pub user_id: Vec<u8>,
	pub timestamp: u64,
	pub coinbase_postfix: Vec<u8>,
	pub remaining_payout: Script,
	pub appended_outputs: Vec<TxOut>,
}
impl PoolPayoutInfo {
	pub fn encode_unsigned(&self, res: &mut bytes::BytesMut) {
		res.reserve(13 + self.user_id.len() + self.coinbase_postfix.len() + self.remaining_payout.len());
		res.put_u8(self.user_id.len() as u8);
		res.put_slice(&self.user_id[..]);

		res.put_u64_le(self.timestamp);

		res.put_u8(self.coinbase_postfix.len() as u8);
		res.put_slice(&self.coinbase_postfix[..]);

		res.put_u16_le(self.remaining_payout.len() as u16);
		res.put_slice(&self.remaining_payout[..]);

		res.put_u8(self.appended_outputs.len() as u8);
		for txout in self.appended_outputs.iter() {
			res.reserve(8 + 2 + txout.script_pubkey.len());
			res.put_u64_le(txout.value);
			res.put_u16_le(txout.script_pubkey.len() as u16);
			res.put_slice(&txout.script_pubkey[..]);
		}
	}
}

#[derive(Clone)]
pub struct PoolDifficulty {
	pub share_target: [u8; 32],
	pub weak_block_target: [u8; 32],
}
impl PoolDifficulty {
	pub fn encode_unsigned(&self, res: &mut bytes::BytesMut) {
		res.reserve(2*32);
		res.put_slice(&self.share_target[..]);
		res.put_slice(&self.weak_block_target[..]);
	}
}

#[derive(Clone)]
pub struct PoolShare {
	pub header_version: u32,
	pub header_prevblock: [u8; 32],
	pub header_time: u32,
	pub header_nbits: u32,
	pub header_nonce: u32,

	pub merkle_rhss: Vec<[u8; 32]>,
	pub coinbase_tx: Transaction,

	pub user_tag: Vec<u8>,
}

#[derive(Clone)]
pub enum WeakBlockAction {
	/// Skips the next n transactions from the original sketch
	SkipN { // 0b00
		n: u8,
	},
	/// Includes the transaction at the current index from the original sketch
	IncludeTx {}, // 0b01
	/// Takes tx at index n from the original sketch (without effecting SkipN/IncludeTx position)
	TakeTx { // 0b10
		n: u16
	},
	/// Adds a new transaction not in the original sketch
	NewTx { // 0b11
		tx: Transaction
	},
}

#[derive(Clone)]
pub struct WeakBlock {
	pub header_version: u32,
	pub header_prevblock: [u8; 32],
	pub header_time: u32,
	pub header_nbits: u32,
	pub header_nonce: u32,

	pub user_tag: Vec<u8>,

	pub txn: Vec<WeakBlockAction>,
}

impl WeakBlock {
	pub fn encode(&self, res: &mut bytes::BytesMut) {
		res.reserve(4*5 + 32 + 1 + self.user_tag.len() + self.txn.len()/4);

		res.put_u32_le(self.header_version);
		res.put_slice(&self.header_prevblock);
		res.put_u32_le(self.header_time);
		res.put_u32_le(self.header_nbits);
		res.put_u32_le(self.header_nonce);

		res.put_u8(self.user_tag.len() as u8);
		res.put_slice(&self.user_tag);

		res.put_u32_le(self.txn.len() as u32);

		let mut action_buff = 0;
		let mut action_count = 0;
		macro_rules! push_action {
			($v: expr) => {
				{
					action_buff <<= 2;
					action_buff |= $v;
					action_count += 1;
					if action_count == 4 {
						res.reserve(1);
						res.put_u8(action_buff);
						action_count = 0;
						action_buff = 0;
					}
				}
			}
		}
		for tx in self.txn.iter() {
			match tx {
				&WeakBlockAction::SkipN { .. } => {
					push_action!(0b00);
				},
				&WeakBlockAction::IncludeTx {} => {
					push_action!(0b01);
				},
				&WeakBlockAction::TakeTx { .. } => {
					push_action!(0b10);
				},
				&WeakBlockAction::NewTx { .. } => {
					push_action!(0b11);
				}
			}
		}
		if action_count != 0 {
			res.reserve(1);
			res.put_u8(action_buff << (8 - 2*action_count));
		}

		for tx in self.txn.iter() {
			match tx {
				&WeakBlockAction::SkipN { n } => {
					res.reserve(1);
					res.put_u8(n);
				},
				&WeakBlockAction::IncludeTx {} => {},
				&WeakBlockAction::TakeTx { n } => {
					res.reserve(2);
					res.put_u16_le(n);
				},
				&WeakBlockAction::NewTx { ref tx } => {
					let tx_enc = network::serialize::serialize(tx).unwrap();
					res.reserve(4 + tx_enc.len());
					res.put_u32_le(tx_enc.len() as u32);
					res.put_slice(&tx_enc[..]);
				}
			}
		}
	}
}

pub enum PoolMessage {
	ProtocolSupport {
		max_version: u16,
		min_version: u16,
		flags: u16,
	},
	ProtocolVersion {
		selected_version: u16,
		flags: u16,
		auth_key: PublicKey,
	},
	GetPayoutInfo {
		user_id: Vec<u8>,
		user_auth: Vec<u8>,
	},
	PayoutInfo {
		signature: Signature,
		payout_info: PoolPayoutInfo,
	},
	ShareDifficulty {
		signature: Signature,
		difficulty: PoolDifficulty,
	},
	Share {
		share: PoolShare,
	},
	WeakBlock {
		sketch: WeakBlock,
	},
	WeakBlockStateReset { },
	NewPoolServer {
		signature: Signature,
		new_host_port: String,
	},
}

pub struct PoolMsgFramer {
	secp_ctx: Secp256k1,
}

impl PoolMsgFramer {
	pub fn new() -> PoolMsgFramer {
		PoolMsgFramer {
			secp_ctx: Secp256k1::new(),
		}
	}
}

impl codec::Encoder for PoolMsgFramer {
	type Item = PoolMessage;
	type Error = io::Error;

	fn encode(&mut self, msg: PoolMessage, res: &mut bytes::BytesMut) -> Result<(), io::Error> {
		match msg {
			PoolMessage::ProtocolSupport { max_version, min_version, flags } => {
				res.reserve(1 + 2*3);
				res.put_u8(1);
				res.put_u16_le(max_version);
				res.put_u16_le(min_version);
				res.put_u16_le(flags);
			},
			PoolMessage::ProtocolVersion { selected_version, flags, ref auth_key } => {
				res.reserve(1 + 2*2 + 33);
				res.put_u8(2);
				res.put_u16_le(selected_version);
				res.put_u16_le(flags);
				res.put_slice(&auth_key.serialize());
			},
			PoolMessage::GetPayoutInfo { ref user_id, ref user_auth } => {
				res.reserve(3 + user_id.len() + user_auth.len());
				res.put_u8(10);
				res.put_u8(user_id.len() as u8);
				res.put_slice(&user_id);
				res.put_u8(user_auth.len() as u8);
				res.put_slice(&user_auth);
			},
			PoolMessage::PayoutInfo { ref signature, ref payout_info } => {
				res.reserve(1 + 33);
				res.put_u8(11);
				res.put_slice(&signature.serialize_compact(&self.secp_ctx));
				payout_info.encode_unsigned(res);
			},
			PoolMessage::ShareDifficulty { ref signature, ref difficulty } => {
				res.reserve(1 + 33 + 32*2);
				res.put_u8(12);
				res.put_slice(&signature.serialize_compact(&self.secp_ctx));
				difficulty.encode_unsigned(res);
			},
			PoolMessage::Share { ref share } => {
				let tx_enc = network::serialize::serialize(&share.coinbase_tx).unwrap();
				res.reserve(1 + 4*4 + 32 + 1 + share.merkle_rhss.len()*32 + 4 + tx_enc.len() + 1 + share.user_tag.len());
				res.put_u8(13);
				res.put_u32_le(share.header_version);
				res.put_slice(&share.header_prevblock);
				res.put_u32_le(share.header_time);
				res.put_u32_le(share.header_nbits);
				res.put_u32_le(share.header_nonce);
				res.put_u8(share.merkle_rhss.len() as u8);
				for rhs in share.merkle_rhss.iter() {
					res.put_slice(rhs);
				}
				res.put_u32_le(tx_enc.len() as u32);
				res.put_slice(&tx_enc[..]);
				res.put_u8(share.user_tag.len() as u8);
				res.put_slice(&share.user_tag[..]);
			},
			PoolMessage::WeakBlock { ref sketch } => {
				res.reserve(1);
				res.put_u8(14);
				sketch.encode(res);
			},
			PoolMessage::WeakBlockStateReset { } => {
				res.reserve(1);
				res.put_u8(15);
			},
			PoolMessage::NewPoolServer { ref signature, ref new_host_port } => {
				res.reserve(1 + 33 + 1 + new_host_port.len());
				res.put_u8(16);
				res.put_slice(&signature.serialize_compact(&self.secp_ctx));
				res.put_u8(new_host_port.len() as u8);
				res.put_slice(new_host_port.as_bytes());
			},
		}
		Ok(())
	}
}


impl codec::Decoder for PoolMsgFramer {
	type Item = PoolMessage;
	type Error = io::Error;

	fn decode(&mut self, bytes: &mut bytes::BytesMut) -> Result<Option<PoolMessage>, io::Error> {
		if bytes.len() == 0 { return Ok(None); }

		let mut read_pos = 1;
		macro_rules! get_slice {
			( $size: expr ) => {
				{
					if bytes.len() < read_pos + $size as usize {
						return Ok(None);
					}
					read_pos += $size as usize;
					&bytes[read_pos - ($size as usize)..read_pos]
				}
			}
		}

		macro_rules! advance_bytes {
			() => {
				bytes.advance(read_pos);
			}
		}

		match bytes[0] {
			1 => {
				let msg = PoolMessage::ProtocolSupport {
					max_version: slice_to_le16(get_slice!(2)),
					min_version: slice_to_le16(get_slice!(2)),
					flags: slice_to_le16(get_slice!(2)),
				};
				advance_bytes!();
				Ok(Some(msg))
			},
			2 => {
				let selected_version = slice_to_le16(get_slice!(2));
				if selected_version != 1 {
					// We don't know how to deserialize anything else...
					return Err(io::Error::new(io::ErrorKind::InvalidData, CodecError))
				}
				let msg = PoolMessage::ProtocolVersion {
					selected_version: selected_version,
					flags: slice_to_le16(get_slice!(2)),
					auth_key: match PublicKey::from_slice(&self.secp_ctx, get_slice!(33)) {
						Ok(key) => key,
						Err(_) => {
							println!("Bad key {}", selected_version);
							return Err(io::Error::new(io::ErrorKind::InvalidData, CodecError))
						}
					}
				};
				advance_bytes!();
				Ok(Some(msg))
			},
			10 => {
				let user_id_len = get_slice!(1)[0];
				let user_id = get_slice!(user_id_len).to_vec();
				let user_auth_len = get_slice!(1)[0];
				let user_auth = get_slice!(user_auth_len).to_vec();

				advance_bytes!();
				Ok(Some(PoolMessage::GetPayoutInfo {
					user_id,
					user_auth,
				}))
			},
			11 => {
				let signature = match Signature::from_compact(&self.secp_ctx, get_slice!(64)) {
					Ok(sig) => sig,
					Err(_) => return Err(io::Error::new(io::ErrorKind::InvalidData, CodecError))
				};
				let user_id_len = get_slice!(1)[0];
				let user_id = get_slice!(user_id_len).to_vec();

				let timestamp = slice_to_le64(get_slice!(8));

				let coinbase_postfix_len = get_slice!(1)[0];
				let coinbase_postfix = get_slice!(coinbase_postfix_len).to_vec();

				let script_len = slice_to_le16(get_slice!(2));
				let script = Script::from(get_slice!(script_len).to_vec());

				let coinbase_output_count = get_slice!(1)[0] as usize;
				let mut appended_coinbase_outputs = Vec::with_capacity(coinbase_output_count);
				for _ in 0..coinbase_output_count {
					let value = slice_to_le64(get_slice!(8));
					let script_len = slice_to_le16(get_slice!(2));
					appended_coinbase_outputs.push(TxOut {
						value: value,
						script_pubkey: Script::from(get_slice!(script_len).to_vec()),
					})
				}

				let msg = PoolMessage::PayoutInfo {
					signature: signature,
					payout_info: PoolPayoutInfo {
						user_id,
						timestamp,
						coinbase_postfix,
						remaining_payout: script,
						appended_outputs: appended_coinbase_outputs,
					}
				};
				advance_bytes!();
				Ok(Some(msg))
			},
			12 => {
				let signature = match Signature::from_compact(&self.secp_ctx, get_slice!(64)) {
					Ok(sig) => sig,
					Err(_) => return Err(io::Error::new(io::ErrorKind::InvalidData, CodecError))
				};
				let mut share_target = [0; 32];
				share_target.copy_from_slice(get_slice!(32));
				let mut weak_block_target = [0; 32];
				weak_block_target.copy_from_slice(get_slice!(32));

				let msg = PoolMessage::ShareDifficulty {
					signature,
					difficulty: PoolDifficulty {
						share_target,
						weak_block_target,
					}
				};
				advance_bytes!();
				Ok(Some(msg))
			},
			13 => {
				let header_version = slice_to_le32(get_slice!(4));
				let mut header_prevblock = [0; 32];
				header_prevblock.copy_from_slice(get_slice!(32));
				let header_time = slice_to_le32(get_slice!(4));
				let header_nbits = slice_to_le32(get_slice!(4));
				let header_nonce = slice_to_le32(get_slice!(4));

				let merkle_rhss_count = get_slice!(1)[0] as usize;
				if merkle_rhss_count > 16 {
					return Err(io::Error::new(io::ErrorKind::InvalidData, CodecError));
				}
				let mut merkle_rhss = Vec::with_capacity(merkle_rhss_count);
				for _ in 0..merkle_rhss_count {
					let mut merkle_rhs = [0; 32];
					merkle_rhs[..].copy_from_slice(get_slice!(32));
					merkle_rhss.push(merkle_rhs);
				}

				let tx_len = slice_to_le32(get_slice!(4));
				if tx_len > 1000000 {
					return Err(io::Error::new(io::ErrorKind::InvalidData, CodecError));
				}
				let coinbase_tx = match network::serialize::deserialize(get_slice!(tx_len)) {
					Ok(tx) => tx,
					Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e))
				};

				let user_tag_len = get_slice!(1)[0];
				let user_tag = get_slice!(user_tag_len).to_vec();

				let msg = PoolMessage::Share {
					share: PoolShare {
						header_version,
						header_prevblock,
						header_time,
						header_nbits,
						header_nonce,

						merkle_rhss,
						coinbase_tx,
						user_tag,
					},
				};
				advance_bytes!();
				Ok(Some(msg))
			},
			14 => {
				let header_version = slice_to_le32(get_slice!(4));
				let mut header_prevblock = [0; 32];
				header_prevblock.copy_from_slice(get_slice!(32));
				let header_time = slice_to_le32(get_slice!(4));
				let header_nbits = slice_to_le32(get_slice!(4));
				let header_nonce = slice_to_le32(get_slice!(4));

				let user_tag_len = get_slice!(1)[0];
				let user_tag = get_slice!(user_tag_len).to_vec();

				let mut actions = Vec::new();

				{
					let action_count = slice_to_le32(get_slice!(4));
					let action_bits = get_slice!((action_count + 3) / 4);

					let mut total_tx_len = 0;
					for action_byte in action_bits {
						for i in 1..5 {
							match (action_byte >> (8 - 2*i)) as u8 & (0b11 as u8) {
								0b00 => {
									let n = get_slice!(1)[0];
									actions.push(WeakBlockAction::SkipN { n });
								},
								0b01 => {
									actions.push(WeakBlockAction::IncludeTx{});
								},
								0b10 => {
									let n = slice_to_le16(get_slice!(2));
									actions.push(WeakBlockAction::TakeTx { n });
								},
								0b11 => {
									let txlen = slice_to_le32(get_slice!(4));
									if txlen > 4000000 || total_tx_len + txlen > 4000000 {
										return Err(io::Error::new(io::ErrorKind::InvalidData, CodecError));
									}
									total_tx_len += txlen;
									actions.push(WeakBlockAction::NewTx { tx: match network::serialize::deserialize(get_slice!(txlen)) {
										Ok(tx) => tx,
										Err(_) => return Err(io::Error::new(io::ErrorKind::InvalidData, CodecError)),
									} });
								},
								_ => unimplemented!(),
							}
							if actions.len() >= action_count as usize { break; }
						}
					}
				}

				advance_bytes!();
				Ok(Some(PoolMessage::WeakBlock {
					sketch: WeakBlock {
						header_version,
						header_prevblock,
						header_time,
						header_nbits,
						header_nonce,
						user_tag,
						txn: actions,
					}
				}))
			},
			15 => {
				advance_bytes!();
				Ok(Some(PoolMessage::WeakBlockStateReset {}))
			},
			16 => {
				let signature = match Signature::from_compact(&self.secp_ctx, get_slice!(64)) {
					Ok(sig) => sig,
					Err(_) => return Err(io::Error::new(io::ErrorKind::InvalidData, CodecError))
				};
				let new_host_port = match String::from_utf8(get_slice!(get_slice!(1)[0]).to_vec()) {
					Ok(string) => string,
					Err(_) => return Err(io::Error::new(io::ErrorKind::InvalidData, CodecError))
				};
				let msg = PoolMessage::NewPoolServer {
					signature,
					new_host_port,
				};
				advance_bytes!();
				Ok(Some(msg))
			},
			_ => {
				return Err(io::Error::new(io::ErrorKind::InvalidData, CodecError))
			}
		}
	}
}
