use msg_framing::{BlockTemplate,WorkInfo,WinningNonce};
use utils;

use bitcoin::blockdata::transaction::{TxIn,Transaction};
use bitcoin::blockdata::script::Script;
use bitcoin::blockdata::block::BlockHeader;
use bitcoin::network::serialize::BitcoinHash;
use bitcoin::util::hash::Sha256dHash;

use crypto::digest::Digest;
use crypto::sha2::Sha256;

use futures::{future,Future,Sink};
use futures::stream::Stream;
use futures::unsync::mpsc;

use tokio::net;
use tokio::executor::current_thread;

use tokio_io::AsyncRead;
use tokio_io::codec;

use serde_json;

use std::cell::RefCell;
use std::char;
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::io;
use std::rc::Rc;

#[derive(Debug)]
struct BadMessageError;
impl fmt::Display for BadMessageError {
	fn fmt(&self, fmt: &mut fmt::Formatter) -> Result<(), fmt::Error> {
		fmt.write_str("Bad stratum message")
	}
}
impl Error for BadMessageError {
	fn description(&self) -> &str {
		"Bad stratum message"
	}
}

fn le64_to_array(u: u64) -> [u8; 8] {
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

fn extend_vec_from_hex(hex: &str, out: &mut Vec<u8>) -> Result<(), BadMessageError> {
	let mut b = 0;
	for (idx, c) in hex.as_bytes().iter().enumerate() {
		b <<= 4;
		match *c {
			b'A'...b'F' => b |= c - b'A' + 10,
			b'a'...b'f' => b |= c - b'a' + 10,
			b'0'...b'9' => b |= c - b'0',
			_ => return Err(BadMessageError),
		}
		if (idx & 1) == 1 {
			out.push(b);
			b = 0;
		}
	}
	Ok(())
}

fn hex_to_be32(hex: &str) -> Result<u32, BadMessageError> {
	if hex.len() != 8 { return Err(BadMessageError); }
	let mut res = 0;
	for c in hex.as_bytes() {
		res <<= 4;
		match *c {
			b'A'...b'F' => res |= (c - b'A' + 10) as u32,
			b'a'...b'f' => res |= (c - b'a' + 10) as u32,
			b'0'...b'9' => res |= (c - b'0') as u32,
			_ => return Err(BadMessageError),
		}
	}
	Ok(res)
}

fn n_to_hexit(b: u32) -> u8 {
	let byte = (b & 0x0f) as u8;
	if byte < 10 {
		b'0' + byte
	} else {
		b'a' + byte - 10
	}
}

fn push_le_32_hex(v: u32, out: &mut String) {
	out.push(n_to_hexit((v >> (4 + 8*0)) & 0x0f) as char);
	out.push(n_to_hexit((v >> (0 + 8*0)) & 0x0f) as char);
	out.push(n_to_hexit((v >> (4 + 8*1)) & 0x0f) as char);
	out.push(n_to_hexit((v >> (0 + 8*1)) & 0x0f) as char);
	out.push(n_to_hexit((v >> (4 + 8*2)) & 0x0f) as char);
	out.push(n_to_hexit((v >> (0 + 8*2)) & 0x0f) as char);
	out.push(n_to_hexit((v >> (4 + 8*3)) & 0x0f) as char);
	out.push(n_to_hexit((v >> (0 + 8*3)) & 0x0f) as char);
}

fn be32_to_hex(v: u32) -> String {
	let mut out = String::with_capacity(8);
	out.push(n_to_hexit((v >> (4 + 8*3)) & 0x0f) as char);
	out.push(n_to_hexit((v >> (0 + 8*3)) & 0x0f) as char);
	out.push(n_to_hexit((v >> (4 + 8*2)) & 0x0f) as char);
	out.push(n_to_hexit((v >> (0 + 8*2)) & 0x0f) as char);
	out.push(n_to_hexit((v >> (4 + 8*1)) & 0x0f) as char);
	out.push(n_to_hexit((v >> (0 + 8*1)) & 0x0f) as char);
	out.push(n_to_hexit((v >> (4 + 8*0)) & 0x0f) as char);
	out.push(n_to_hexit((v >> (0 + 8*0)) & 0x0f) as char);
	out
}

fn len_to_compact_size(len: u32, out: &mut String) {
	if len < 253 {
		out.push(n_to_hexit((len >> (4 + 8*0)) & 0x0f) as char);
		out.push(n_to_hexit((len >> (0 + 8*0)) & 0x0f) as char);
	} else if len < (1 << 16) {
		out.push_str("fd");
		out.push(n_to_hexit((len >> (4 + 8*0)) & 0x0f) as char);
		out.push(n_to_hexit((len >> (0 + 8*0)) & 0x0f) as char);
		out.push(n_to_hexit((len >> (4 + 8*1)) & 0x0f) as char);
		out.push(n_to_hexit((len >> (0 + 8*1)) & 0x0f) as char);
	} else {
		out.push_str("fe");
		push_le_32_hex(len, out);
	}
}

fn push_bytes_hex(bytes: &[u8], out: &mut String) {
	for i in 0..bytes.len() {
		out.push(char::from_digit((bytes[i] >> 4) as u32, 16).unwrap());
		out.push(char::from_digit((bytes[i] & 0x0f) as u32, 16).unwrap());
	}
}

fn bytes_to_hex(bytes: &[u8]) -> String {
	let mut ret = String::with_capacity(bytes.len() * 2);
	push_bytes_hex(bytes, &mut ret);
	ret
}

/// Stratum byte-swaps the previous block field, but only in 4-byte chunks....because batshit
/// insanity
fn bytes_to_hex_insane_order(bytes: &[u8; 32]) -> String {
	let mut out = String::with_capacity(bytes.len() * 2);
	for i in 0..32/4 {
		out.push(char::from_digit((bytes[i * 4 + 3] >> 4) as u32, 16).unwrap());
		out.push(char::from_digit((bytes[i * 4 + 3] & 0x0f) as u32, 16).unwrap());
		out.push(char::from_digit((bytes[i * 4 + 2] >> 4) as u32, 16).unwrap());
		out.push(char::from_digit((bytes[i * 4 + 2] & 0x0f) as u32, 16).unwrap());
		out.push(char::from_digit((bytes[i * 4 + 1] >> 4) as u32, 16).unwrap());
		out.push(char::from_digit((bytes[i * 4 + 1] & 0x0f) as u32, 16).unwrap());
		out.push(char::from_digit((bytes[i * 4 + 0] >> 4) as u32, 16).unwrap());
		out.push(char::from_digit((bytes[i * 4 + 0] & 0x0f) as u32, 16).unwrap());
	}
	out
}

const EXTRANONCE2_SIZE: usize = 8;
const VERSION_MASK: u32 = 0x1fffe000;
fn job_to_json_string(template: &BlockTemplate, prev_changed: bool) -> String {
	let mut coinbase_prev = String::with_capacity(4*2 + 1*2 + 36*2 + 1*2 + template.coinbase_prefix.len() + 8*2);
	push_le_32_hex(template.coinbase_version, &mut coinbase_prev);
	coinbase_prev.push_str("01");
	coinbase_prev.push_str("0000000000000000000000000000000000000000000000000000000000000000ffffffff");
	// Add size of extranonce + 8 bytes for client id
	let coinbase_len = template.coinbase_prefix.len() + 8 + EXTRANONCE2_SIZE;
	coinbase_prev.push(char::from_digit(((coinbase_len >> 4) & 0x0f) as u32, 16).unwrap());
	coinbase_prev.push(char::from_digit(((coinbase_len >> 0) & 0x0f) as u32, 16).unwrap());
	push_bytes_hex(&template.coinbase_prefix[..], &mut coinbase_prev);

	let mut coinbase_post = String::new();
	push_le_32_hex(template.coinbase_input_sequence, &mut coinbase_post);
	coinbase_post.push(char::from_digit(((template.appended_coinbase_outputs.len() >> 4) & 0x0f) as u32, 16).unwrap());
	coinbase_post.push(char::from_digit(((template.appended_coinbase_outputs.len() >> 0) & 0x0f) as u32, 16).unwrap());
	for output in template.appended_coinbase_outputs.iter() {
		push_le_32_hex(output.value as u32, &mut coinbase_post);
		push_le_32_hex((output.value >> 4*8) as u32, &mut coinbase_post);
		len_to_compact_size(output.script_pubkey.len() as u32, &mut coinbase_post);
		push_bytes_hex(&output.script_pubkey[..], &mut coinbase_post);
	}
	push_le_32_hex(template.coinbase_locktime, &mut coinbase_post);

	let mut merkle_rhss = Vec::with_capacity(template.merkle_rhss.len());
	for rhs in template.merkle_rhss.iter() {
		merkle_rhss.push(bytes_to_hex(rhs));
	}

	json!({
		"params": [
			template.template_id.to_string(),
			bytes_to_hex_insane_order(&template.header_prevblock),
			coinbase_prev,
			coinbase_post,
			merkle_rhss,
			be32_to_hex(template.header_version),
			be32_to_hex(template.header_nbits),
			be32_to_hex(template.header_time),
			prev_changed,
		],
		"id": serde_json::Value::Null,
		"method": "mining.notify",
	}).to_string()
}

fn job_to_difficulty_string(template: &BlockTemplate) -> String {
	json!({
		"params": [
			utils::target_to_diff_lb(&template.target),
		],
		"id": serde_json::Value::Null,
		"method": "mining.set_difficulty",
	}).to_string()
}

struct StratumClient {
	stream: mpsc::Sender<String>,
	client_id: u64,
	subscribed: bool,
}

pub struct StratumServer {
	clients: Vec<Rc<RefCell<StratumClient>>>,
	client_id_max: u64,
	// TODO: Limit size of jobs by evicting old ones
	jobs: BTreeMap<u64, WorkInfo>,
}

impl StratumServer {
	pub fn new(job_providers: mpsc::Receiver<WorkInfo>) -> Rc<RefCell<Self>> {
		let us = Rc::new(RefCell::new(Self {
			clients: Vec::new(),
			client_id_max: 0,
			jobs: BTreeMap::new(),
		}));

		let us_cp = us.clone();
		let mut last_prevblock = [0; 32];
		let mut last_diff = [0; 32];
		current_thread::spawn(job_providers.for_each(move |job| {
			macro_rules! announce_str {
				($str: expr) => {
					us_cp.borrow_mut().clients.retain(|ref it| {
						let mut client = it.borrow_mut();
						if !client.subscribed { return true; }
						match client.stream.start_send($str.clone()) {
							Ok(_) => true,
							Err(_) => false
						}
					});
				}
			}

			let prev_changed = last_prevblock != job.template.header_prevblock;
			if prev_changed {
				last_prevblock = job.template.header_prevblock;
			}
			let diff_changed = last_diff != job.template.target;
			if diff_changed {
				last_diff = job.template.target;
				let diff_str = job_to_difficulty_string(&job.template);
				announce_str!(diff_str);
			}

			let job_json = job_to_json_string(&job.template, prev_changed);
			announce_str!(job_json);
			us_cp.borrow_mut().jobs.insert(job.template.template_id, job);
			future::result(Ok(()))
		}));

		us
	}

	pub fn new_connection(rc: Rc<RefCell<Self>>, stream: net::TcpStream) {
		stream.set_nodelay(true).unwrap();

		let (tx, rx) = stream.framed(codec::LinesCodec::new()).split();

		let client_ref = {
			let (send_sink, send_stream) = mpsc::channel(5);
			current_thread::spawn(tx.send_all(send_stream.map_err(|_| -> io::Error {
				panic!("mpsc streams cant generate errors!");
			})).then(|_| {
				future::result(Ok(()))
			}));

			let mut us = rc.borrow_mut();
			let client = Rc::new(RefCell::new(StratumClient {
				stream: send_sink,
				client_id: us.client_id_max,
				subscribed: false,
			}));
			println!("Got new client connection (id {})", us.client_id_max);
			us.client_id_max += 1;

			let client_ref = client.clone();
			us.clients.push(client);
			client_ref
		};

		let rc_close = rc.clone();
		let client_ref_close = client_ref.clone();

		//TODO: Set a timer for the client to always push *something* to them every 30 seconds or
		//so, as otherwise stratum clients time out.

		current_thread::spawn(rx.for_each(move |line| -> future::FutureResult<(), io::Error> {
			println!("Got line from {}: {}", client_ref.borrow().client_id, line);
			let json = match serde_json::from_str::<serde_json::Value>(&line) {
				Ok(v) => {
					if !v.is_object() {
						return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, BadMessageError)));
					}
					v
				},
				Err(e) => return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, e)))
			};
			if !json.is_object() {
				return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, BadMessageError)));
			}
			let msg = json.as_object().unwrap();
			if !msg.contains_key("method") || !msg.contains_key("id") || !msg.contains_key("params") {
				return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, BadMessageError)));
			}
			if !msg["method"].is_string() {
				return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, BadMessageError)));
			}

			let mut client = client_ref.borrow_mut();

			macro_rules! send_response {
				($err: expr, $res: tt) => {
					let msg_str = json!({
						"error": $err,
						"id": msg["id"],
						"result": $res,
					}).to_string();
					println!("Sending command to {}: {}", client.client_id, msg_str);
					match client.stream.start_send(msg_str) {
						Err(_) => return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, BadMessageError))),
						Ok(_) => {}
					}
				}
			}

			match msg["method"].as_str().unwrap() {
				"mining.subscribe" => {
					let mut client_id_str = String::with_capacity(16);
					push_le_32_hex(client.client_id as u32, &mut client_id_str);
					push_le_32_hex((client.client_id >> 32) as u32, &mut client_id_str);
					send_response!(serde_json::Value::Null,
						[
							[ "mining.notify", &client_id_str ],
							client_id_str,
							EXTRANONCE2_SIZE,
						]);
					match rc.borrow().jobs.iter().last() { //TODO: This is ineffecient, map should have a last()
						Some(job) => {
							let diff_string = job_to_difficulty_string(&job.1.template);
							println!("Sending command to {}: {}", client.client_id, diff_string);
							match client.stream.start_send(diff_string) {
								Err(_) => return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, BadMessageError))),
								Ok(_) => {}
							}
							let job_string = job_to_json_string(&job.1.template, true);
							println!("Sending command to {}: {}", client.client_id, job_string);
							match client.stream.start_send(job_string) {
								Err(_) => return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, BadMessageError))),
								Ok(_) => {}
							}
						}, None => {}
					}
					client.subscribed = true;
				},
				"mining.submit" => {
					if !msg["params"].is_array() || msg["params"].as_array().unwrap().len() < 5 {
						return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, BadMessageError)));
					}
					let params = msg["params"].as_array().unwrap();
					for (idx, param) in params.iter().enumerate() {
						if !param.is_string() {
							return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, BadMessageError)));
						}
						if idx == 2 && param.as_str().unwrap().len() != EXTRANONCE2_SIZE*2 {
							return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, BadMessageError)));
						}
						if (idx == 3 || idx == 4) && param.as_str().unwrap().len() != 8 {
							return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, BadMessageError)));
						}
					}

					let job_id = match params[1].as_str().unwrap().parse() {
						Err(_) => return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, BadMessageError))),
						Ok(id) => id,
					};
					let time = match hex_to_be32(params[3].as_str().unwrap()) {
						Err(_) => return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, BadMessageError))),
						Ok(time) => time,
					};
					let nonce = match hex_to_be32(params[4].as_str().unwrap()) {
						Err(_) => return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, BadMessageError))),
						Ok(nonce) => nonce,
					};

					match rc.borrow_mut().jobs.get(&job_id) {
						Some(job) => {
							let version = if params.len() >= 6 {
								match hex_to_be32(params[5].as_str().unwrap()) {
									Err(_) => return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, BadMessageError))),
									Ok(version) => (version & VERSION_MASK) | (job.template.header_version & !VERSION_MASK),
								}
							} else { job.template.header_version };

							let mut script_sig = job.template.coinbase_prefix.clone();
							script_sig.extend_from_slice(&le64_to_array(client.client_id));
							match extend_vec_from_hex(params[2].as_str().unwrap(), &mut script_sig) {
								Ok(_) => {},
								Err(_) => return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, BadMessageError))),
							}

							let coinbase_tx = Transaction {
								version: job.template.coinbase_version,
								input: vec!(TxIn {
									prev_hash: Default::default(),
									prev_index: 0xffffffff,
									script_sig: Script::from(script_sig),
									sequence: job.template.coinbase_input_sequence,
								}),
								output: job.template.appended_coinbase_outputs.clone(),
								witness: vec!(),
								lock_time: job.template.coinbase_locktime,
							};

							let mut merkle_lhs = [0; 32];
							merkle_lhs.copy_from_slice(&coinbase_tx.txid()[..]);
							let mut sha = Sha256::new();
							for rhs in job.template.merkle_rhss.iter() {
								sha.reset();
								sha.input(&merkle_lhs);
								sha.input(&rhs[..]);
								sha.result(&mut merkle_lhs);
								sha.reset();
								sha.input(&merkle_lhs);
								sha.result(&mut merkle_lhs);
							}

							let block_hash = BlockHeader {
								version: version,
								prev_blockhash: Sha256dHash::from(&job.template.header_prevblock[..]),
								merkle_root: Sha256dHash::from(&merkle_lhs[..]),
								time: time,
								bits: job.template.header_nbits,
								nonce: nonce,
							}.bitcoin_hash();

							if utils::does_hash_meet_target(&block_hash[..], &job.template.target[..]) {
								match job.solutions.unbounded_send(Rc::new((WinningNonce {
									template_id: job.template.template_id,
									header_version: version,
									header_time: time,
									header_nonce: nonce,
									coinbase_tx: coinbase_tx,
								}, block_hash))) {
									Ok(_) => {},
									Err(_) => { panic!(); },
								};
								send_response!(serde_json::Value::Null, true);
							} else {
								println!("Got work that missed target (hashed to {}, which is greater than {})", bytes_to_hex(&block_hash[..]), bytes_to_hex(&job.template.target[..]));
								send_response!(serde_json::Value::Null, false);

							}
						},
						None => {
							send_response!("Invalid job_id or job timed out", false);
						},
					}
				},
				"mining.authorize" => {
					send_response!(serde_json::Value::Null, true);
				},
				"mining.get_transactions" => {
					send_response!(serde_json::Value::Null, []);
				},
				"mining.configure" => {
					if !msg["params"].is_array() || msg["params"].as_array().unwrap().len() != 2 {
						return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, BadMessageError)));
					}
					let params = msg["params"].as_array().unwrap();
					if !params[0].is_array() || params[1].is_object() {
						return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, BadMessageError)));
					}
					for ext in params[0].as_array().unwrap().iter() {
						match ext.as_str() {
							Some("version-rolling") => {
								match params[1].as_object().unwrap().get("version-rolling.mask") {
									Some(ref mask) => {
										let mask_value: u32 = match mask.as_str() {
											Some(mask_str) => {
												match mask_str.parse() {
													Err(_) => return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, BadMessageError))),
													Ok(v) => v,
												}
											},
											None => return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, BadMessageError)))
										};
										send_response!(serde_json::Value::Null, {
											"version-rolling": true,
											"version-rolling.mask": be32_to_hex(mask_value & VERSION_MASK),
										});
										return future::result(Ok(()))
									},
									None => {}
								};
							},
							None => {
								return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, BadMessageError)));
							}
							_ => {},
						}
					}
					send_response!(serde_json::Value::Null, {});
				},
				_ => {
					return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, BadMessageError)))
				}
			};
			future::result(Ok(()))
		}).then(move |_| {
			let mut us = rc_close.borrow_mut();
			us.clients.retain(|client| {
				!Rc::ptr_eq(&client_ref_close, client)
			});
			println!("Client {} disconnected, now have {} clients!", client_ref_close.borrow().client_id, us.clients.len());
			future::result(Ok(()))
		}));
	}
}
