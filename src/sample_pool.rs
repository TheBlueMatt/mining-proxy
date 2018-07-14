// Simple sample pool server that implements most of what you need, note that it does NOT currently
// check for duplicate shares...

extern crate base64;
extern crate bitcoin;
extern crate bytes;
extern crate crypto;
extern crate futures;
extern crate hyper;
extern crate tokio;
extern crate tokio_io;
extern crate tokio_codec;
extern crate secp256k1;
extern crate serde_json;

mod msg_framing;
use msg_framing::*;

mod utils;

mod rpc_client;
use rpc_client::*;

mod generational_hash_sets;
use generational_hash_sets::*;

mod timeout_stream;
use timeout_stream::TimeoutStream;

use bitcoin::blockdata::transaction::Transaction;
use bitcoin::blockdata::block::BlockHeader;
use bitcoin::network::serialize::BitcoinHash;
use bitcoin::network;
use bitcoin::util::address::Address;
use bitcoin::util::privkey;
use bitcoin::util::hash::Sha256dHash;

use bytes::BufMut;

use crypto::digest::Digest;
use crypto::sha2::Sha256;

use futures::{future,Stream,Sink,Future};
use futures::sync::mpsc;

use tokio::{net, timer};

use secp256k1::key::PublicKey;
use secp256k1::Secp256k1;

use std::{cmp, env, io, mem};
use std::str::FromStr;
use std::sync::{Arc, Weak, Mutex, RwLock};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH, Duration, Instant};
use std::collections::{hash_map, HashMap, HashSet};


#[cfg(feature = "kafka_submitter")]
extern crate serde;
#[cfg(feature = "kafka_submitter")]
extern crate rdkafka;
#[cfg(feature = "kafka_submitter")]
#[macro_use]
extern crate serde_derive;

// Kafka submitter
#[cfg(feature = "kafka_submitter")]
mod kafka_submitter;
#[cfg(feature = "kafka_submitter")]
use kafka_submitter::*;

// Redis authenticator
#[cfg(feature = "redis_authenticator")]
mod redis_authenticator;
#[cfg(feature = "redis_authenticator")]
use redis_authenticator::*;

// Generic submitter and authenticator
#[cfg(not(feature = "kafka_submitter"))]
mod generic_submitter;
#[cfg(not(feature = "kafka_submitter"))]
use generic_submitter::*;

#[cfg(not(feature = "redis_authenticator"))]
mod generic_authenticator;
#[cfg(not(feature = "redis_authenticator"))]
use generic_authenticator::*;

// You can change these consts as settings:

// Note that because leading_0s_to_target gets the *largest* number with the given number of
// leading 0s, we offset by 1 higher than we really want (this limits stratum false-positives
// in the naive difficulty converter).

const MIN_TARGET_LEADING_0S: u8 = 47; // Diff ~16384
const WEAK_BLOCK_RATIO_0S: u8 = 8; // 2**8x harder to mine weak blocks
const MAX_USER_SHARES_PER_30_SEC: usize = 30;
const MIN_USER_SHARES_PER_30_SEC: usize = 2;

// Dont change anything below...
const MAX_TARGET_LEADING_0S: u8 = 71 - WEAK_BLOCK_RATIO_0S; // Roughly network diff/16 at the time of writing, should be more than sufficiently high for any use-case

struct PerUserClientRef {
	send_stream: mpsc::Sender<PoolMessage>,
	client_id: u64,
	user_id: Vec<u8>,
	min_target: u8,
	cur_target: AtomicUsize,
	accepted_shares: AtomicUsize,
	submitted_header_hashes: GenerationalHashSets,
}

struct AllowedBlocksInfo {
	/// hash -> chainwork
	allowed_prev_blocks: HashMap<[u8; 32], [u8; 32]>,
	best_chainwork: [u8; 32],
	cur_target: [u8; 32],
	old_prev_blocks: HashSet<[u8; 32]>,
	tentative_submitted_prev_blocks: HashSet<[u8; 32]>,
	users_ref: Arc<Mutex<Vec<Weak<PerUserClientRef>>>>,
}
enum HeaderStatus {
	TentativeAccept,
	TentativeReject,
	Absurd,
}
impl AllowedBlocksInfo {
	fn update_chainwork(&mut self, chainwork: [u8; 32]) {
		println!("New best-seen-block, rejecting old blocks now!");
		let old_prev_blocks = &mut self.old_prev_blocks;
		let mut blocks_wiped = Vec::with_capacity(2);
		self.allowed_prev_blocks.retain(|prev_hash, old_chainwork| {
			if !utils::does_hash_meet_target(&chainwork, old_chainwork) { // !(chainwork <= old_chainwork) ie old_chainwork < chainwork
				old_prev_blocks.insert(prev_hash.clone());
				blocks_wiped.push(prev_hash.clone());
				false
			} else { true }
		});
		self.best_chainwork = chainwork;
		let users_ref = self.users_ref.clone();
		tokio::spawn(future::lazy(move || {
			let users = users_ref.lock().unwrap().clone();
			for user_ref in users {
				if let Some(user) = user_ref.upgrade() {
					for block_hash in blocks_wiped.iter() {
						user.submitted_header_hashes.wipe_generation(block_hash);
					}
				}
			}
			Ok(())
		}));
	}

	fn check_block(&mut self, header: &serde_json::Value) {
		if let Some(serde_json::Value::String(chainwork_v)) = header.get("chainwork") {
			if let Some(serde_json::Value::String(hash_v)) = header.get("hash") {
				if let Some(serde_json::Value::Number(confs_v)) = header.get("confirmations") {
					if let Some(confs) = confs_v.as_i64() {
						if let Some(chainwork) = utils::hex_to_u256_rev(&chainwork_v) {
							if let Some(hash) = utils::hex_to_u256_rev(&hash_v) {
								let equal_or_better = utils::does_hash_meet_target(&self.best_chainwork, &chainwork);
								if self.best_chainwork == chainwork {
									println!("New header tied with current tip!");
									self.allowed_prev_blocks.insert(hash, chainwork);
								} else if confs >= 0 && equal_or_better {
									self.update_chainwork(chainwork.clone());
									self.allowed_prev_blocks.insert(hash, chainwork);
								} else if equal_or_better {
									println!("Got new header with more work, waiting on block validation to reject stale shares");
									self.allowed_prev_blocks.insert(hash, chainwork);
								} else {
									self.old_prev_blocks.insert(hash);
								}
							}
						}
					}
				}
			}
		}
	}

	fn submit_header(us: &Arc<RwLock<Self>>, header: BlockHeader, client: &Arc<RPCClient>) -> HeaderStatus {
		let blockhash = header.bitcoin_hash();
		let mut hash_arr = [0; 32];
		hash_arr[..].copy_from_slice(&blockhash[..]);
		if utils::count_leading_zeros(&hash_arr) < 32 {
			// They can't even be mining after genesis, kick them
			return HeaderStatus::Absurd;
		}

		let mut us_lock = us.write().unwrap();
		if !utils::does_hash_meet_target_div4(&hash_arr, &us_lock.cur_target) {
			// They are definitely out-of-date, but may not be trying to DoS us (or we're
			// out-of-date and still syncing)
			return HeaderStatus::TentativeReject;
		}

		// We'd really like to only use div4 here, since that is actually the consensus-rule, but
		// BCash might conceivably get 25% of Bitcoin's hashrate, allowing someone to (very briefly)
		// mine BCash-based shares. Once BCash dies off we should just remove this check.
		let res = if utils::does_hash_meet_target_div2(&hash_arr, &us_lock.cur_target) {
			us_lock.tentative_submitted_prev_blocks.insert(hash_arr);
			HeaderStatus::TentativeAccept
		} else { HeaderStatus::TentativeReject };

		let us_clone = us.clone();
		let client_clone = client.clone();
		tokio::spawn(client.make_rpc_call("submitblockheader", &vec![&("\"".to_string() + &network::serialize::serialize_hex(&header).unwrap() + "\"")]).then(move |_| {
			client_clone.make_rpc_call("getblockheader", &vec![&("\"".to_string() + &blockhash.be_hex_string() + "\"")]).then(move |header_data_option| {
				let mut us_lock = us_clone.write().unwrap();
				if let Ok(header_data) = header_data_option {
					us_lock.check_block(&header_data);
				}
				us_lock.tentative_submitted_prev_blocks.remove(&hash_arr);
				Ok(())
			})
		}));

		res
	}
}

fn main() {
	println!("USAGE: sample-pool --listen_bind=IP:port --auth_key=base58privkey --payout_address=addr [--server_id=up_to_36_byte_string_for_coinbase] --bitcoind_rpc_path=user:pass@host:port");
	println!("--listen_bind - the address to bind to");
	println!("--auth_key - the auth key to use to authenticate to clients");
	println!("--payout_address - the Bitcoin address on which to receive payment");
	println!("--bitcoind_rpc_path - the bitcoind RPC server for checking weak block validity");
	println!("                      and header submission");
	print_submitter_parameters();
	print_authenticator_parameters();

	let mut listen_bind = None;
	let mut auth_key = None;
	let mut payout_addr = None;
	let mut server_id = None;
	let mut rpc_path = None;

	let mut submitter_settings = init_submitter_settings();
	let mut authenticator_settings = init_authenticator_settings();

	for arg in env::args().skip(1) {
		if arg.starts_with("--listen_bind") {
			if listen_bind.is_some() {
				println!("Cannot specify multiple listen binds");
				return;
			}
			listen_bind = Some(match arg.split_at(14).1.parse() {
				Ok(sockaddr) => sockaddr,
				Err(_) =>{
					println!("Failed to parse listen_bind into a socket address");
					return;
				}
			});
		} else if arg.starts_with("--auth_key") {
			if auth_key.is_some() {
				println!("Cannot specify multiple auth keys");
				return;
			}
			auth_key = Some(match privkey::Privkey::from_str(arg.split_at(11).1) {
				Ok(privkey) => {
					if !privkey.compressed {
						println!("Private key must represent a compressed key!");
						return;
					}
					privkey.key
				},
				Err(_) =>{
					println!("Failed to parse auth_key into a private key");
					return;
				}
			});
		} else if arg.starts_with("--payout_address") {
			if payout_addr.is_some() {
				println!("Cannot specify multiple payout addresses");
				return;
			}
			//TODO: check network magic byte? We're allowed to mine on any net, though...
			payout_addr = Some(match Address::from_str(arg.split_at(17).1) {
				Ok(addr) => addr.script_pubkey(),
				Err(_) => {
					println!("Failed to parse payout_address into a Bitcoin address");
					return;
				}
			});
		} else if arg.starts_with("--server_id") {
			if server_id.is_some() {
				println!("Cannot specify multiple server IDs");
				return;
			}
			server_id = Some(arg.split_at(12).1.to_string());
			if server_id.as_ref().unwrap().len() > 36 {
				println!("server_id cannot be longer than 36 bytes");
				return;
			}
		} else if arg.starts_with("--bitcoind_rpc_path") {
			if rpc_path.is_some() {
				println!("Cannot specify multiple bitcoinds");
				return;
			}
			rpc_path = Some(arg.split_at(20).1.to_string());
		} else if parse_submitter_parameter(&mut submitter_settings, &arg) {
			// Submitter did something useful!
		} else if parse_authenticator_parameter(&mut authenticator_settings, &arg) {
			// So as Authenticator!
		} else {
			println!("Unkown arg: {}", arg);
			return;
		}
	}

	let submitter_state = Arc::new(setup_submitter(submitter_settings));
	let authenticator_state = Arc::new(setup_authenticator(authenticator_settings));

	if listen_bind.is_none() || auth_key.is_none() || payout_addr.is_none() || rpc_path.is_none() {
		println!("Need to specify all but server_id parameters");
		return;
	}

	let users: Arc<Mutex<Vec<Weak<PerUserClientRef>>>> = Arc::new(Mutex::new(Vec::new()));
	let block_info = Arc::new(RwLock::new(AllowedBlocksInfo {
		allowed_prev_blocks: HashMap::new(),
		best_chainwork: [0; 32],
		cur_target: [0xff; 32],
		old_prev_blocks: HashSet::new(),
		tentative_submitted_prev_blocks: HashSet::new(),
		users_ref: users.clone(),
	}));

	let rpc_client = {
		let path = rpc_path.unwrap();
		let path_parts: Vec<&str> = path.split('@').collect();
		if path_parts.len() != 2 {
			println!("Bad RPC URL provided");
			return;
		}
		Arc::new(RPCClient::new(path_parts[0], path_parts[1]))
	};

	{
		println!("Checking validity of RPC URL");
		let mut thread_rt = tokio::runtime::current_thread::Runtime::new().unwrap();
		let block_info_clone = block_info.clone();
		let rpc_client = rpc_client.clone();
		if let Err(_) = thread_rt.block_on(rpc_client.make_rpc_call("getblockcount", &Vec::new()).and_then(move |block_count| {
			let min_height = block_count.as_i64().unwrap();
			rpc_client.make_rpc_call("getchaintips", &Vec::new()).and_then(move |chaintips| {
				let mut all_futures = Vec::new();
				for entry in chaintips.as_array().unwrap() {
					if entry.get("height").unwrap().as_i64().unwrap() >= min_height {
						let status = entry.get("status").unwrap().as_str().unwrap();
						if status != "invalid" {
							let block_info = block_info_clone.clone();
							all_futures.push(rpc_client.make_rpc_call("getblockheader", &vec![&("\"".to_string() + entry.get("hash").unwrap().as_str().unwrap() + "\"")]).and_then(move |header| {
								block_info.write().unwrap().check_block(&header);
								Ok(())
							}));
						}
					}
				}
				future::join_all(all_futures)
			})
		})) {
			println!("Failed");
			return;
		}
		println!("Success! Starting up...");
	}

	let mut rt = tokio::runtime::Builder::new().build().unwrap();

	let block_info_clone = block_info.clone();
	let rpc_client_clone = rpc_client.clone();
	let best_block_hash = Arc::new(Mutex::new(String::new()));
	rt.spawn(timer::Interval::new(Instant::now() + Duration::from_secs(1), Duration::from_millis(50)).for_each(move |_| {
		let best_block_hash_clone = best_block_hash.clone();
		let block_info = block_info_clone.clone();
		rpc_client_clone.make_rpc_call("getblockchaininfo", &Vec::new()).and_then(move |chain_info| {
			if let Some(serde_json::Value::String(besthash_v)) = chain_info.get("bestblockhash") {
				if *besthash_v != *best_block_hash_clone.lock().unwrap() {
					if let Some(serde_json::Value::String(targethash_v)) = chain_info.get("target") {
						if let Some(serde_json::Value::String(chainwork_v)) = chain_info.get("chainwork") {
							if let Some(targethash) = utils::hex_to_u256_rev(&targethash_v) {
								if let Some(chainwork) = utils::hex_to_u256_rev(&chainwork_v) {
									if let Some(besthash) = utils::hex_to_u256_rev(&besthash_v) {
										*best_block_hash_clone.lock().unwrap() = besthash_v.to_string();
										let mut info_lock = block_info.write().unwrap();
										info_lock.cur_target = targethash;
										info_lock.update_chainwork(chainwork.clone());
										info_lock.allowed_prev_blocks.insert(besthash, chainwork);
									}
								}
							}
						}
					} else {
						println!("WARNING: RPC server is incompatible (not providing a getblockchaininfo target)!");
					}
				}
			}
			future::result(Ok(()))
		}).then(|_| {
			future::result(Ok(()))
		})
	}).then(|_| {
		future::result(Ok(()))
	}));

	rt.spawn(futures::lazy(move || -> Result<(), ()> {
		match net::TcpListener::bind(&listen_bind.unwrap()) {
			Ok(listener) => {
				let mut max_client_id = 0;

				let users_timer_ref = users.clone();
				tokio::spawn(timer::Interval::new(Instant::now() + Duration::from_secs(10), Duration::from_secs(30)).for_each(move |_| {
					let mut users_lock = users_timer_ref.lock().unwrap();
					let time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
					let timestamp = time.as_secs() * 1000 + time.subsec_nanos() as u64 / 1_000_000;

					users_lock.retain(|weak_user| {
						match weak_user.upgrade() {
							Some(user) => {
								let shares = user.accepted_shares.swap(0, Ordering::AcqRel);
								let cur_target = user.cur_target.load(Ordering::Acquire) as u8;
								println!("In last 30 seconds, user with id {} submitted {} shares with {} leading zeros", user.client_id, shares, cur_target);

								let new_target = if shares > MAX_USER_SHARES_PER_30_SEC && cur_target < MAX_TARGET_LEADING_0S {
									cur_target + 1
								} else if shares < MIN_USER_SHARES_PER_30_SEC && cur_target > MIN_TARGET_LEADING_0S && cur_target > user.min_target {
									cur_target - 1
								} else {
									cur_target
								};
								if new_target != cur_target {
									let _ = user.send_stream.clone().start_send(PoolMessage::ShareDifficulty {
										difficulty: PoolDifficulty {
											user_id: user.user_id.clone(),
											timestamp,
											share_target: utils::leading_0s_to_target(new_target as u8),
											weak_block_target: utils::leading_0s_to_target(new_target + WEAK_BLOCK_RATIO_0S),
										},
									});
									user.cur_target.store(new_target as usize, Ordering::Release);
								}

								true
							},
							None => { false }
						}
					});

					future::result(Ok(()))
				}).then(|_| {
					future::result(Ok(()))
				}));

				tokio::spawn(listener.incoming().for_each(move |sock| {
					sock.set_nodelay(true).unwrap();

					let (tx, rx) = tokio_codec::Framed::new(sock, PoolMsgFramer::new()).split();
					let (mut send_sink, send_stream) = mpsc::channel(5);
					tokio::spawn(tx.send_all(send_stream.map_err(|_| -> io::Error {
						panic!("mpsc streams cant generate errors!");
					})).then(|_| {
						future::result(Ok(()))
					}));

					let secp_ctx = Secp256k1::new();
					macro_rules! sign_message {
						($msg: expr, $msg_type: expr) => {
							{
								let mut msg_signed = bytes::BytesMut::with_capacity(1000);
								msg_signed.put_u8($msg_type);
								$msg.encode_unsigned(&mut msg_signed);
								let hash = {
									let mut sha = Sha256::new();
									sha.input(&msg_signed[..]);
									let mut h = [0; 32];
									sha.result(&mut h);
									secp256k1::Message::from_slice(&h).unwrap()
								};

								secp_ctx.sign(&hash, &auth_key.unwrap()).unwrap()
							}
						}
					}

					let users_ref = users.clone();
					let server_id_vec = match server_id {
						Some(ref id) => id.as_bytes().to_vec(),
						None => vec![],
					};
					let payout_addr_clone = payout_addr.as_ref().unwrap().clone();

					let mut connection_clients = HashMap::new();
					let mut client_ids = HashMap::new();

					let mut client_version = None;
					let mut last_weak_block = None;

					let block_info_clone = block_info.clone();
					let rpc_client_clone = rpc_client.clone();
					let submitter_state = submitter_state.clone();
					let authenticator_state = authenticator_state.clone();

					tokio::spawn(TimeoutStream::new(rx, Duration::from_secs(60*10)).for_each(move |msg| {
						macro_rules! send_response {
							($msg: expr) => {
								match send_sink.start_send($msg) {
									Ok(_) => {},
									Err(_) => return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError)))
								}
							}
						}

						macro_rules! reject_share {
							($share_msg: expr, $reason: expr) => {
								{
									send_response!(PoolMessage::ShareRejected {
										user_tag_1: $share_msg.user_tag_1.clone(),
										user_tag_2: $share_msg.user_tag_2.clone(),
										reason: $reason,
									});
								}
							}
						}

						macro_rules! check_prev_hash {
							($msg: expr, $header_option: expr, $extra_fail_cmd: expr) => {
								let need_submit = {
									let allowed_lock = block_info_clone.read().unwrap();
									if !allowed_lock.allowed_prev_blocks.contains_key(&$msg.header_prevblock) {
										if !allowed_lock.tentative_submitted_prev_blocks.contains(&$msg.header_prevblock) {
											if allowed_lock.old_prev_blocks.contains(&$msg.header_prevblock) {
												reject_share!($msg, ShareRejectedReason::StalePrevBlock);
												$extra_fail_cmd;
												return future::result(Ok(()));
											} else {
												if $header_option.is_some() {
													true
												} else {
													reject_share!($msg, ShareRejectedReason::StalePrevBlock);
													$extra_fail_cmd;
													return future::result(Ok(()));
												}
											}
										} else { false }
									} else { false }
								};
								if need_submit {
									let header = $header_option.unwrap();
									match AllowedBlocksInfo::submit_header(&block_info_clone, header, &rpc_client_clone) {
										HeaderStatus::TentativeAccept => {},
										HeaderStatus::TentativeReject => {
											reject_share!($msg, ShareRejectedReason::StalePrevBlock);
											$extra_fail_cmd;
											return future::result(Ok(()));
										},
										HeaderStatus::Absurd => {
											println!("Got absurd previous header from client!");
											return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError)));
										}
									}
								}
							}
						}

						macro_rules! check_coinbase_tx {
							($coinbase_tx: expr, $share_msg: expr, $extra_fail_cmd: expr) => {
								{
									if $coinbase_tx.input.len() != 1 || $coinbase_tx.output.len() < 1 {
										reject_share!($share_msg, ShareRejectedReason::BadPayoutInfo);
										$extra_fail_cmd;
										return future::result(Ok(()));
									}

									let mut our_payout = 0;
									for (idx, out) in $coinbase_tx.output.iter().enumerate() {
										if idx == 0 {
											our_payout = out.value;
											if out.script_pubkey != payout_addr_clone {
												reject_share!($share_msg, ShareRejectedReason::BadPayoutInfo);
												$extra_fail_cmd;
												return future::result(Ok(()));
											}
										} else if out.value != 0 {
											reject_share!($share_msg, ShareRejectedReason::BadPayoutInfo);
											$extra_fail_cmd;
											return future::result(Ok(()));
										}
									}

									let coinbase = &$coinbase_tx.input[0].script_sig[..];
									if coinbase.len() < 8 {
										reject_share!($share_msg, ShareRejectedReason::BadPayoutInfo);
										$extra_fail_cmd;
										return future::result(Ok(()));
									}

									let client_id = if let Some(client_id) = client_ids.get(&utils::slice_to_le64(&coinbase[coinbase.len() - 8..])) {
										client_id
									} else {
										reject_share!($share_msg, ShareRejectedReason::BadPayoutInfo);
										$extra_fail_cmd;
										return future::result(Ok(()));
									};

									(our_payout, client_id)
								}
							}
						}

						macro_rules! share_received {
							($user: expr, $cur_target: expr, $share_msg: expr) => {
								{
									send_response!(PoolMessage::ShareAccepted {
										user_tag_1: $share_msg.user_tag_1.clone(),
										user_tag_2: $share_msg.user_tag_2.clone(),
									});
									let accepted_shares = $user.accepted_shares.fetch_add(1, Ordering::AcqRel);
									if accepted_shares + 1 > MAX_USER_SHARES_PER_30_SEC && $cur_target < MAX_TARGET_LEADING_0S {
										let time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
										let timestamp = time.as_secs() * 1000 + time.subsec_nanos() as u64 / 1_000_000;

										send_response!(PoolMessage::ShareDifficulty {
											difficulty: PoolDifficulty {
												user_id: $user.user_id.clone(),
												timestamp,
												share_target: utils::leading_0s_to_target($cur_target + 1),
												weak_block_target: utils::leading_0s_to_target($cur_target + 1 + WEAK_BLOCK_RATIO_0S),
											},
										});
										$user.cur_target.store(($cur_target + 1) as usize, Ordering::Release);
										$user.accepted_shares.store((accepted_shares + 1) / 2, Ordering::Release);
									}
								}
							}
						}

						match msg {
							PoolMessage::ProtocolSupport { max_version, min_version, flags } => {
								if client_version.is_some() {
									println!("Client sent duplicative ProtocolSupport");
									return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError)));
								}
								if min_version > 1 || max_version < 1 {
									return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError)));
								}
								if flags != 0 {
									println!("Client requested unknown flags {}", flags);
								}
								client_version = Some(1);
								send_response!(PoolMessage::ProtocolVersion {
									selected_version: 1,
									flags: 0,
									auth_key: PublicKey::from_secret_key(&secp_ctx, &auth_key.unwrap()).unwrap(),
								});

								let time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
								let timestamp = time.as_secs() * 1000 + time.subsec_nanos() as u64 / 1_000_000;
								let payout_info = PoolPayoutInfo {
									timestamp,
									remaining_payout: payout_addr_clone.clone(),
									appended_outputs: vec![],
								};
								send_response!(PoolMessage::PayoutInfo {
									signature: sign_message!(payout_info, 13),
									payout_info,
								});
							},
							PoolMessage::ProtocolVersion { .. } => {
								println!("Got ProtocolVersion?");
								return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError)));
							},
							PoolMessage::UserAuth { info } => {
								let time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
								let timestamp = time.as_secs() * 1000 + time.subsec_nanos() as u64 / 1_000_000;

								if client_version.is_none() {
									println!("Client sent UserAuth before ProtocolSupport");
									return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError)));
								}
								if {
									let connection_entry = connection_clients.entry(info.user_id.clone());
									if let hash_map::Entry::Occupied(_) = connection_entry {
										println!("Got a UserAuth for an already-registered client, disconencting proxy!");
										return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError)));
									}
									if check_user_auth(&*authenticator_state, &info.user_id, &info.user_auth) {
										let client_id = max_client_id;
										max_client_id += 1;

										println!("Got new user with id {} for client id {}", utils::bytes_to_hex(&info.user_id), client_id);

										let mut client_coinbase_postfix = server_id_vec.clone();
										client_coinbase_postfix.extend_from_slice(&utils::le64_to_array(client_id));

										let initial_target = cmp::min(MAX_TARGET_LEADING_0S, cmp::max(MIN_TARGET_LEADING_0S, cmp::max(utils::count_leading_zeros(&info.suggested_target) + 1, utils::count_leading_zeros(&info.minimum_target) + 1)));
										let user = Arc::new(PerUserClientRef {
											send_stream: send_sink.clone(),
											client_id,
											user_id: info.user_id.clone(),
											min_target: utils::count_leading_zeros(&info.minimum_target) + 1,
											cur_target: AtomicUsize::new(initial_target as usize),
											accepted_shares: AtomicUsize::new(0),
											submitted_header_hashes: GenerationalHashSets::new(),
										});
										client_ids.insert(client_id, info.user_id.clone());
										connection_entry.or_insert(user.clone());
										users_ref.lock().unwrap().push(Arc::downgrade(&user));

										let user_payout_info = PoolUserPayoutInfo {
											user_id: info.user_id.clone(),
											timestamp,
											coinbase_postfix: client_coinbase_postfix.clone(),
										};
										send_response!(PoolMessage::AcceptUserAuth {
											signature: sign_message!(user_payout_info, 15),
											info: user_payout_info,
										});

										send_response!(PoolMessage::ShareDifficulty {
											difficulty: PoolDifficulty {
												user_id: info.user_id.clone(),
												timestamp,
												share_target: utils::leading_0s_to_target(initial_target),
												weak_block_target: utils::leading_0s_to_target(initial_target + WEAK_BLOCK_RATIO_0S),
											},
										});
										false
									} else { true }
								} {
									if connection_clients.is_empty() {
										return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError)));
									} else {
										send_response!(PoolMessage::RejectUserAuth { user_id: info.user_id });
										return future::result(Ok(()));
									}
								}
							},
							PoolMessage::PayoutInfo { .. } => {
								println!("Got PayoutInfo?");
								return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError)));
							},
							PoolMessage::AcceptUserAuth { .. } => {
								println!("Got AcceptUserAuth?");
								return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError)));
							},
							PoolMessage::RejectUserAuth { .. } => {
								println!("Got RejectUserAuth?");
								return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError)));
							},
							PoolMessage::DropUser { user_id } => {
								if let Some(client_ref) = connection_clients.remove(&user_id) {
									client_ids.remove(&client_ref.client_id);
								} else {
									println!("Got DropUser for an un-authed user");
									return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError)));
								}
							},
							PoolMessage::ShareDifficulty { .. } => {
								println!("Got ShareDifficulty?");
								return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError)));
							},
							PoolMessage::Share { ref share } => {
								if client_version.is_none() || connection_clients.is_empty() {
									println!("Client sent Share before version/id handshake");
									return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError)));
								}

								check_prev_hash!(share, share.previous_header, {});

								let (our_payout, client_id) = check_coinbase_tx!(share.coinbase_tx, share, {});

								let mut merkle_lhs = [0; 32];
								merkle_lhs.copy_from_slice(&share.coinbase_tx.txid()[..]);
								let mut sha = Sha256::new();
								for rhs in share.merkle_rhss.iter() {
									sha.reset();
									sha.input(&merkle_lhs);
									sha.input(&rhs[..]);
									sha.result(&mut merkle_lhs);
									sha.reset();
									sha.input(&merkle_lhs);
									sha.result(&mut merkle_lhs);
								}

								let block_header = BlockHeader {
									version: share.header_version,
									prev_blockhash: Sha256dHash::from(&share.header_prevblock[..]),
									merkle_root: Sha256dHash::from(&merkle_lhs[..]),
									time: share.header_time,
									bits: share.header_nbits,
									nonce: share.header_nonce,
								};
								let block_hash = block_header.bitcoin_hash();
								let leading_zeros = utils::count_leading_zeros(&block_hash[..]);

								let client = connection_clients.get(client_id).unwrap();
								let client_target = client.cur_target.load(Ordering::Acquire) as u8;

								if leading_zeros >= client_target + WEAK_BLOCK_RATIO_0S {
									println!("Got share that met weak block target, ignored as we'll check the weak block");
								} else if leading_zeros >= client_target {
									if client.submitted_header_hashes.try_insert(&share.header_prevblock, block_hash) {
										share_submitted(&*submitter_state, client_id, &share.user_tag_1, our_payout, &block_header, leading_zeros, client_target);
										share_received!(client, client_target, share);
									} else {
										reject_share!(share, ShareRejectedReason::Duplicate);
									}
								} else {
									reject_share!(share, ShareRejectedReason::BadHash);
								}
							},
							PoolMessage::WeakBlock { mut sketch } => {
								if client_version.is_none() || connection_clients.is_empty() {
									println!("Client sent Share before version/id handshake");
									return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError)));
								}
								if sketch.txn.len() < 1 {
									println!("Client sent WeakBlock with no transactions");
									return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError)));
								}

								// We reset the weak block state and just return early
								// here...shouldn't be much loss in doing so as all the
								// transactions they included are going to be useless once they get
								// the new block anyway.
								let dummy_header: Option<BlockHeader> = None;
								check_prev_hash!(sketch, dummy_header, send_response!(PoolMessage::WeakBlockStateReset {}));

								let (coinbase_txid, (our_payout, client_id)) = match &sketch.txn[0] {
									&WeakBlockAction::TakeTx { .. } => {
										reject_share!(sketch, ShareRejectedReason::BadWork);
										send_response!(PoolMessage::WeakBlockStateReset {});
										return future::result(Ok(()));
									},
									&WeakBlockAction::NewTx { ref tx } => {
										let tx_deser_attempt: Result<Transaction, _> = network::serialize::deserialize(tx);
										match tx_deser_attempt {
											Ok(tx_deser) => {
												(tx_deser.txid(), check_coinbase_tx!(tx_deser, sketch, send_response!(PoolMessage::WeakBlockStateReset {})))
											},
											Err(_) => {
												reject_share!(sketch, ShareRejectedReason::BadPayoutInfo);
												send_response!(PoolMessage::WeakBlockStateReset {});
												return future::result(Ok(()));
											}
										}
									},
								};

								let mut merkle_lhs = [0; 32];
								merkle_lhs.copy_from_slice(&coinbase_txid[..]);
								let mut sha = Sha256::new();
								for rhs in sketch.merkle_rhss.iter() {
									sha.reset();
									sha.input(&merkle_lhs);
									sha.input(&rhs[..]);
									sha.result(&mut merkle_lhs);
									sha.reset();
									sha.input(&merkle_lhs);
									sha.result(&mut merkle_lhs);
								}

								let header = BlockHeader {
									version: sketch.header_version,
									prev_blockhash: Sha256dHash::from(&sketch.header_prevblock[..]),
									merkle_root: Sha256dHash::from(&merkle_lhs[..]),
									time: sketch.header_time,
									bits: sketch.header_nbits,
									nonce: sketch.header_nonce,
								};

								let mut new_txn = Vec::with_capacity(sketch.txn.len());
								{
									let mut dummy_last_weak_block: Vec<Vec<u8>> = Vec::new();
									let last_weak_ref = if last_weak_block.is_some() {
										last_weak_block.as_mut().unwrap()
									} else { &mut dummy_last_weak_block };

									for action in sketch.txn.drain(..) {
										match action {
											WeakBlockAction::TakeTx { n } => {
												if n as usize >= last_weak_ref.len() {
													reject_share!(sketch, ShareRejectedReason::BadWork);
													send_response!(PoolMessage::WeakBlockStateReset {});
													return future::result(Ok(()));
												}
												new_txn.push(Vec::new());
												mem::swap(&mut last_weak_ref[n as usize], &mut new_txn.last_mut().unwrap());
											},
											WeakBlockAction::NewTx { tx } => {
												new_txn.push(tx);
											}
										}
									}
								}

								let block_hash = header.bitcoin_hash();
								let leading_zeros = utils::count_leading_zeros(&block_hash[..]);

								let client = connection_clients.get(client_id).unwrap();
								let client_target = client.cur_target.load(Ordering::Acquire) as u8;

								if leading_zeros >= client_target + WEAK_BLOCK_RATIO_0S {
									if client.submitted_header_hashes.try_insert(&sketch.header_prevblock, block_hash) {
										weak_block_submitted(&*submitter_state, client_id, &sketch.user_tag_1, our_payout, &header, &new_txn, &sketch.extra_block_data, leading_zeros, client_target);
										share_received!(client, client_target, sketch);
									} else {
										reject_share!(sketch, ShareRejectedReason::Duplicate);
									}
								} else {
									reject_share!(sketch, ShareRejectedReason::BadHash);
								}

								last_weak_block = Some(new_txn);
							},
							PoolMessage::WeakBlockStateReset { } => {
								println!("Got WeakBlockStateReset?");
								return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError)));
							},
							PoolMessage::ShareAccepted { .. } => {
								println!("Got ShareAccepted?");
								return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError)));
							},
							PoolMessage::ShareRejected { .. } => {
								println!("Got ShareRejected?");
								return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError)));
							},
							PoolMessage::NewPoolServer { .. } => {
								println!("Got NewPoolServer?");
								return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError)));
							},
							PoolMessage::VendorMessage { .. } => {
								println!("Got vendor message");
								return future::result(Ok(()));
							},
						}
						future::result(Ok(()))
					}).then(|_| {
						future::result(Ok(()))
					}));

					future::result(Ok(()))
				}).then(|_| {
					future::result(Ok(()))
				}));
			},
			Err(_) => {
				println!("Failed to bind to listen bind addr");
				return Ok(())
			}
		};

		Ok(())
	}));
	rt.shutdown_on_idle().wait().unwrap();
}
