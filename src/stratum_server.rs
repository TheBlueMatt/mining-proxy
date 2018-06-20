use msg_framing::{BlockTemplate,WinningNonce};
use work_getter::WorkInfo;
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
use futures::sync::mpsc;

use tokio;
use tokio::{net, timer};

use tokio_codec;

use serde_json;

use std::{char, cmp, fmt, io, mem};
use std::collections::BTreeMap;
use std::error::Error;
use std::sync::{Arc, Mutex, RwLock};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH, Duration, Instant};

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
	let mut coinbase_prev = String::with_capacity(4*2 + 1*2 + 36*2 + 1*2 + template.coinbase_prefix.len()*2);
	push_le_32_hex(template.coinbase_version, &mut coinbase_prev);
	coinbase_prev.push_str("01");
	coinbase_prev.push_str("0000000000000000000000000000000000000000000000000000000000000000ffffffff");
	// Add size of extranonce + 8 bytes for client id
	let coinbase_len = template.coinbase_prefix.len() + 8 + EXTRANONCE2_SIZE + template.coinbase_postfix.len();
	coinbase_prev.push(char::from_digit(((coinbase_len >> 4) & 0x0f) as u32, 16).unwrap());
	coinbase_prev.push(char::from_digit(((coinbase_len >> 0) & 0x0f) as u32, 16).unwrap());
	utils::push_bytes_hex(&template.coinbase_prefix[..], &mut coinbase_prev);

	let mut coinbase_post = String::new();
	utils::push_bytes_hex(&template.coinbase_postfix[..], &mut coinbase_post);
	push_le_32_hex(template.coinbase_input_sequence, &mut coinbase_post);
	coinbase_post.push(char::from_digit(((template.appended_coinbase_outputs.len() >> 4) & 0x0f) as u32, 16).unwrap());
	coinbase_post.push(char::from_digit(((template.appended_coinbase_outputs.len() >> 0) & 0x0f) as u32, 16).unwrap());
	for output in template.appended_coinbase_outputs.iter() {
		push_le_32_hex(output.value as u32, &mut coinbase_post);
		push_le_32_hex((output.value >> 4*8) as u32, &mut coinbase_post);
		len_to_compact_size(output.script_pubkey.len() as u32, &mut coinbase_post);
		utils::push_bytes_hex(&output.script_pubkey[..], &mut coinbase_post);
	}
	push_le_32_hex(template.coinbase_locktime, &mut coinbase_post);

	let mut merkle_rhss = Vec::with_capacity(template.merkle_rhss.len());
	for rhs in template.merkle_rhss.iter() {
		merkle_rhss.push(utils::bytes_to_hex(rhs));
	}

	json!({
		"params": [
			template.template_timestamp.to_string(),
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

#[cfg(not(any(target_pointer_width = "32", target_pointer_width = "64")))]
const ERR: () = "You need at least 32 bit pointers (well, usize, but we'll assume they're the same) to use any of this stuff";

struct StratumClient {
	stream: mpsc::Sender<String>,
	client_id: u64,
	last_send: Mutex<Instant>,
	subscribed: AtomicBool,
}

pub struct StratumServer {
	clients: Mutex<(Vec<Arc<StratumClient>>, u64)>,
	jobs: RwLock<BTreeMap<u64, WorkInfo>>,
}

impl StratumServer {
	pub fn new(job_providers: mpsc::UnboundedReceiver<WorkInfo>) -> Arc<Self> {
		let us = Arc::new(Self {
			clients: Mutex::new((Vec::new(), 0)),
			jobs: RwLock::new(BTreeMap::new()),
		});

		let us_cp = us.clone();
		let mut last_prevblock = [0; 32];
		let mut last_diff = [0; 32];
		tokio::spawn(job_providers.for_each(move |job| {
			{
				let new_job = job.clone();
				let mut jobs = us_cp.jobs.write().unwrap();
				jobs.insert(job.template.template_timestamp, new_job);
			}

			let prev_changed = last_prevblock != job.template.header_prevblock;
			if prev_changed {
				last_prevblock = job.template.header_prevblock;
			}
			let diff_changed = last_diff != job.template.target;
			let mut diff_str = String::new();
			if diff_changed {
				last_diff = job.template.target;
				diff_str = job_to_difficulty_string(&job.template);
			}
			let job_json = job_to_json_string(&job.template, prev_changed);

			let clients = us_cp.clients.lock().unwrap().0.clone();
			for client in clients {
				if !client.subscribed.load(Ordering::Acquire) { continue; }
				let mut client_stream = client.stream.clone();
				if diff_changed {
					let _ = client_stream.start_send(diff_str.clone());
				}
				let _ = client_stream.start_send(job_json.clone());
				*client.last_send.lock().unwrap() = Instant::now();
			}

			future::result(Ok(()))
		}));

		let us_timer = us.clone(); // Wait, you wanted a deconstructor? LOL
		tokio::spawn(timer::Interval::new(Instant::now() + Duration::from_secs(10), Duration::from_secs(1)).for_each(move |_| {
			let last_job = {
				let time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
				let timestamp = (time.as_secs() - 30) * 1000 + time.subsec_nanos() as u64 / 1_000_000;

				let jobs = us_timer.jobs.read().unwrap();
				let last_job = match jobs.iter().last() { //TODO: This is ineffecient, map should have a last()
					Some((_, v)) => Some(v.clone()),
					None => None,
				};

				if { // Avoid write lock unless we need it
					let res = {
						if jobs.len() > 1 {
							let mut iter = jobs.iter();
							iter.next(); // We have to keep a job until the next one is 30 seconds old
							if let Some((k, _)) = iter.next() {
								*k < timestamp
							} else { false }
						} else { false }
					};
					mem::drop(jobs);
					res
				} {
					let mut jobs = us_timer.jobs.write().unwrap();
					while jobs.len() > 1 {
						// There should be a much easier way to implement this...
						let (first_timestamp, second_timestamp) = {
							let mut iter = jobs.iter();
							(*iter.next().unwrap().0, *iter.next().unwrap().0)
						};
						if second_timestamp < timestamp {
							jobs.remove(&first_timestamp);
						} else { break; }
					}
				}

				last_job
			};

			match last_job {
				Some(job) => {
					let now = Instant::now();
					let send_target = now - Duration::from_secs(29);
					let job_string = job_to_json_string(&job.template, false);
					let mut clients = us_timer.clients.lock().unwrap().0.clone();
					for client in clients.iter() {
						if client.subscribed.load(Ordering::Acquire) && *client.last_send.lock().unwrap() < send_target {
							let mut client_stream = client.stream.clone();
							match client_stream.start_send(job_string.clone()) {
								Ok(_) => *client.last_send.lock().unwrap() = now,
								Err(_) => {},
							}
						}
					}
				}, None => {}
			}

			future::result(Ok(()))
		}).then(|_| {
			future::result(Ok(()))
		}));
		us
	}

	pub fn new_connection(us: Arc<Self>, stream: net::TcpStream) {
		stream.set_nodelay(true).unwrap();

		let (tx, rx) = tokio_codec::Framed::new(stream, tokio_codec::LinesCodec::new()).split();

		let (client, mut send_sink) = {
			let (send_sink, send_stream) = mpsc::channel(5);
			tokio::spawn(tx.send_all(send_stream.map_err(|_| -> io::Error {
				unreachable!();
			})).then(|_| {
				future::result(Ok(()))
			}));

			let sink_dup = send_sink.clone();

			let mut client_list = us.clients.lock().unwrap();
			let client = Arc::new(StratumClient {
				stream: send_sink,
				client_id: client_list.1,
				last_send: Mutex::new(Instant::now()),
				subscribed: AtomicBool::new(false),
			});
			println!("Got new client connection (id {})", client_list.1);
			client_list.1 += 1;

			let client_ref = client.clone();
			client_list.0.push(client);
			(client_ref, sink_dup)
		};

		let client_close = client.clone();
		let us_close = us.clone();

		tokio::spawn(rx.for_each(move |line| -> future::FutureResult<(), io::Error> {
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

			macro_rules! send_response {
				($err: expr, $res: tt) => {
					let msg_str = json!({
						"error": $err,
						"id": msg["id"],
						"result": $res,
					}).to_string();
					match send_sink.start_send(msg_str) {
						Err(_) => return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, BadMessageError))),
						Ok(_) => {}
					}
				}
			}

			match msg["method"].as_str().unwrap() {
				"mining.subscribe" => {
					send_response!(serde_json::Value::Null,
						[
							[ "mining.notify", "" ],
							"", // dummy value, we'll set it for real in mining.authorize
							EXTRANONCE2_SIZE,
						]);
					let jobs = us.jobs.read().unwrap();
					match jobs.iter().last() { //TODO: This is ineffecient, map should have a last()
						Some(job) => {
							let diff_string = job_to_difficulty_string(&job.1.template);
							match send_sink.start_send(diff_string) {
								Err(_) => return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, BadMessageError))),
								Ok(_) => {}
							}
							let job_string = job_to_json_string(&job.1.template, true);
							match send_sink.start_send(job_string) {
								Err(_) => return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, BadMessageError))),
								Ok(_) => {}
							}
						}, None => {}
					}
					*client.last_send.lock().unwrap() = Instant::now();
					client.subscribed.store(true, Ordering::Release);
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

					let jobs = us.jobs.read().unwrap();
					match jobs.get(&job_id) {
						Some(job) => {
							let version = if params.len() >= 6 {
								match hex_to_be32(params[5].as_str().unwrap()) {
									Err(_) => return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, BadMessageError))),
									Ok(version) => (version & VERSION_MASK) | (job.template.header_version & !VERSION_MASK),
								}
							} else { job.template.header_version };

							let mut script_sig = job.template.coinbase_prefix.clone();
							script_sig.extend_from_slice(&utils::le64_to_array(client.client_id));
							match extend_vec_from_hex(params[2].as_str().unwrap(), &mut script_sig) {
								Ok(_) => {},
								Err(_) => return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, BadMessageError))),
							}
							script_sig.extend_from_slice(&job.template.coinbase_postfix[..]);

							let coinbase_tx = Transaction {
								version: job.template.coinbase_version,
								input: vec!(TxIn {
									prev_hash: Default::default(),
									prev_index: 0xffffffff,
									script_sig: Script::from(script_sig),
									sequence: job.template.coinbase_input_sequence,
									witness: vec!(),
								}),
								output: job.template.appended_coinbase_outputs.clone(),
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

							let user_tag_bytes = params[0].as_str().unwrap().as_bytes();
							let user_tag = user_tag_bytes[0..cmp::min(user_tag_bytes.len(), 255)].to_vec();

							if utils::does_hash_meet_target(&block_hash[..], &job.template.target[..]) {
								match job.solutions.unbounded_send(Arc::new((WinningNonce {
									template_timestamp: job.template.template_timestamp,
									header_version: version,
									header_time: time,
									header_nonce: nonce,
									coinbase_tx: coinbase_tx,
									user_tag: user_tag,
								}, block_hash))) {
									Ok(_) => {},
									Err(_) => { unreachable!(); },
								};
								send_response!(serde_json::Value::Null, true);
							} else if utils::does_hash_meet_target_div4(&block_hash[..], &job.template.target[..]) {
								println!("Got work that missed target, but which (probably) met the stratum diff");
								send_response!(serde_json::Value::Null, true);
							} else {
								println!("Got work that missed target (hashed to {}, which is greater than {})", utils::bytes_to_hex(&block_hash[..]), utils::bytes_to_hex(&job.template.target[..]));
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
					let mut client_id_str = String::with_capacity(16);
					push_le_32_hex(client.client_id as u32, &mut client_id_str);
					push_le_32_hex((client.client_id >> 32) as u32, &mut client_id_str);
					match send_sink.start_send(json!({
						"params": [
							client_id_str,
							EXTRANONCE2_SIZE,
						],
						"id": serde_json::Value::Null,
						"method": "mining.set_extranonce",
					}).to_string()) {
						Err(_) => return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, BadMessageError))),
						Ok(_) => {}
					}
				},
				"mining.get_transactions" => {
					send_response!(serde_json::Value::Null, []);
				},
				"mining.configure" => {
					if !msg["params"].is_array() || msg["params"].as_array().unwrap().len() != 2 {
						return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, BadMessageError)));
					}
					let params = msg["params"].as_array().unwrap();
					if !params[0].is_array() || !params[1].is_object() {
						return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, BadMessageError)));
					}
					for ext in params[0].as_array().unwrap().iter() {
						match ext.as_str() {
							Some("version-rolling") => {
								match params[1].as_object().unwrap().get("version-rolling.mask") {
									Some(ref mask) => {
										let mask_value: u32 = match mask.as_str() {
											Some(mask_str) => {
												match u32::from_str_radix(mask_str, 16) {
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
				"mining.multi_version" => {
					// Some insane bitmain ASICBoost thing?
				},
				_ => {
					return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, BadMessageError)))
				}
			};
			future::result(Ok(()))
		}).then(move |_| {
			let mut clients = us_close.clients.lock().unwrap();
			clients.0.retain(|client| {
				!Arc::ptr_eq(&client_close, client)
			});
			println!("Client {} disconnected, now have {} clients!", client_close.client_id, clients.0.len());
			future::result(Ok(()))
		}));
	}
}
