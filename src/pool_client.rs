use connection_maintainer::*;
use msg_framing::*;
use utils;

use futures::sync::mpsc;

use bitcoin::network;
use bitcoin::blockdata::block::BlockHeader;
use bitcoin::util::hash::Sha256dHash;

use bytes;
use bytes::BufMut;

use future;
use futures::{Future, Stream, Sink};

use tokio;

use crypto::digest::Digest;
use crypto::sha2::Sha256;

use secp256k1;
use secp256k1::key::PublicKey;
use secp256k1::Secp256k1;

use std;
use std::collections::HashMap;
use std::collections::hash_map;
use std::{cmp, io};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone)]
pub struct PoolProviderJob {
	pub payout_info: PoolPayoutInfo,
	pub provider: Arc<PoolHandler>,
}

#[derive(Clone)]
pub struct PoolProviderUserJob {
	pub coinbase_postfix: Vec<u8>,
	pub target: [u8; 32],
}

pub enum PoolProviderAction {
	ProviderDisconnected,
	PoolUpdate { info: PoolProviderJob },
	UserUpdate { user_id: Vec<u8>, update: PoolProviderUserJob },
	UserReject { user_id: Vec<u8> },
}

struct PoolHandlerState {
	stream: Option<mpsc::UnboundedSender<PoolMessage>>,
	auth_key: Option<PublicKey>,

	users_to_reauth: Vec<PoolUserAuth>,

	coinbase_postfix_to_difficulty: HashMap<Vec<u8>, PoolDifficulty>,
	coinbase_postfix_len: Option<u8>,
	/// user_id -> (payout_info.timestamp, payout_info.coinbase_postfix, index in users_to_reauth)
	/// Note that we keep a dummy entry with a 0 timestamp if we've started auth but haven't heard
	/// back yet.
	user_id_to_postfix: HashMap<Vec<u8>, (u64, Vec<u8>, usize)>,

	cur_payout_info: Option<PoolPayoutInfo>,

	last_header_sent: [u8; 32],
	last_weak_block: Option<Vec<Vec<u8>>>,

	job_stream: mpsc::Sender<PoolProviderAction>,
}
struct PoolHandlerStateRefs<'a> {
	stream: &'a mut Option<mpsc::UnboundedSender<PoolMessage>>,
	users_to_reauth: &'a mut Vec<PoolUserAuth>,
	coinbase_postfix_to_difficulty: &'a mut HashMap<Vec<u8>, PoolDifficulty>,
	coinbase_postfix_len: &'a mut Option<u8>,
	user_id_to_postfix: &'a mut HashMap<Vec<u8>, (u64, Vec<u8>, usize)>,
	last_header_sent: &'a mut [u8; 32],
	last_weak_block: &'a mut Option<Vec<Vec<u8>>>,
	job_stream: &'a mut mpsc::Sender<PoolProviderAction>,
}
impl PoolHandlerState {
	fn borrow_mut(&mut self) -> PoolHandlerStateRefs {
		PoolHandlerStateRefs {
			stream: &mut self.stream,
			users_to_reauth: &mut self.users_to_reauth,
			coinbase_postfix_to_difficulty: &mut self.coinbase_postfix_to_difficulty,
			coinbase_postfix_len: &mut self.coinbase_postfix_len,
			user_id_to_postfix: &mut self.user_id_to_postfix,
			last_header_sent: &mut self.last_header_sent,
			last_weak_block: &mut self.last_weak_block,
			job_stream: &mut self.job_stream,
		}
	}
}

pub struct PoolHandler {
	state: RwLock<PoolHandlerState>,
	secp_ctx: Secp256k1,
}

pub enum PoolAuthAction {
	AuthUser(PoolUserAuth),
	DropUser(Vec<u8>),
}

impl PoolHandler {
	pub fn new(expected_auth_key: Option<PublicKey>, user_auth_requests: mpsc::Receiver<PoolAuthAction>) -> (Arc<PoolHandler>, mpsc::Receiver<PoolProviderAction>) {
		let (work_sender, work_receiver) = mpsc::channel(25);

		let us = Arc::new(PoolHandler {
			state: RwLock::new(PoolHandlerState {
				stream: None,
				auth_key: expected_auth_key,

				users_to_reauth: vec![],

				coinbase_postfix_to_difficulty: HashMap::new(),
				coinbase_postfix_len: None,
				user_id_to_postfix: HashMap::new(),

				cur_payout_info: None,

				last_header_sent: [0; 32],
				last_weak_block: None,

				job_stream: work_sender,
			}),
			secp_ctx: Secp256k1::new(),
		});

		let us_auth = us.clone();
		// TODO: Ensure that user_auth_requests message sending never interferes with share
		// submission somehow by blocking it
		tokio::spawn(user_auth_requests.for_each(move |auth_action| {
			let mut lock = us_auth.state.write().unwrap();
			let refs = lock.borrow_mut();
			match auth_action {
				PoolAuthAction::AuthUser(user_id_auth) => {
					let mut val = match refs.user_id_to_postfix.entry(user_id_auth.user_id.clone()) {
						hash_map::Entry::Occupied(_) => panic!("Duplicate user auth request!"),
						hash_map::Entry::Vacant(e) => e.insert((0, Vec::new(), 0)),
					};

					if let &mut Some(ref mut stream) = refs.stream {
						let _ = stream.start_send(PoolMessage::UserAuth { info: user_id_auth.clone() });
					}

					refs.users_to_reauth.push(user_id_auth);
					val.2 = refs.users_to_reauth.len() - 1;
				},
				PoolAuthAction::DropUser(user_id) => {
					let (timestamp, postfix, to_reauth_posn) = refs.user_id_to_postfix.remove(&user_id).unwrap();
					if timestamp != 0 {
						refs.coinbase_postfix_to_difficulty.remove(&postfix).unwrap();
					}
					refs.users_to_reauth.swap_remove(to_reauth_posn);
					if refs.users_to_reauth.len() > to_reauth_posn {
						refs.user_id_to_postfix.get_mut(&refs.users_to_reauth[to_reauth_posn].user_id).unwrap().2 = to_reauth_posn;
					}
					if let &mut Some(ref mut stream) = refs.stream {
						let _ = stream.start_send(PoolMessage::DropUser { user_id });
					}
				}
			}
			Ok(())
		}));

		(us, work_receiver)
	}

	pub fn send_nonce(&self, work: &(WinningNonce, Sha256dHash), template: &Arc<BlockTemplate>, post_coinbase_txn: &Vec<Vec<u8>>, prev_header: &BlockHeader, extra_block_data: &Vec<u8>) {
		let mut us_lock = self.state.write().unwrap();
		let us = us_lock.borrow_mut();

		let previous_header = if *us.last_header_sent == template.header_prevblock { None } else {
			*us.last_header_sent = template.header_prevblock.clone();
			Some(prev_header.clone())
		};

		if let Some(coinbase_postfix_match_len) = *us.coinbase_postfix_len {
			let coinbase_postfix = if work.0.coinbase_tx.input.len() == 1 {
				let coinbase = &work.0.coinbase_tx.input[0].script_sig;
				if coinbase.len() < coinbase_postfix_match_len as usize { return; }
				coinbase[coinbase.len() - coinbase_postfix_match_len as usize..].to_vec()
			} else { return; };

			if let Some(ref difficulty) = us.coinbase_postfix_to_difficulty.get(&coinbase_postfix) {
				if utils::does_hash_meet_target(&work.1[..], &difficulty.share_target[..]) {
					match us.stream {
						&mut Some(ref stream) => {
							match stream.unbounded_send(PoolMessage::Share {
								share: PoolShare {
									header_version: work.0.header_version,
									header_prevblock: template.header_prevblock.clone(),
									header_time: work.0.header_time,
									header_nbits: template.header_nbits,
									header_nonce: work.0.header_nonce,
									merkle_rhss: template.merkle_rhss.clone(),
									coinbase_tx: work.0.coinbase_tx.clone(),
									user_tag_1: work.0.user_tag.clone(),
									user_tag_2: Vec::new(),
									previous_header,
								}
							}) {
								Ok(_) => { println!("Submitted share!"); },
								//TODO: We should queue these for sending later
								Err(_) => {
									println!("Failed to submit nonce as pool connection lost");
									return;
								},
							}
						},
						&mut None => {
							//TODO: We should queue these for sending later
							println!("Failed to submit nonce as pool connection lost");
							return;
						}
					}
				}
				if utils::does_hash_meet_target(&work.1[..], &difficulty.weak_block_target[..]) {
					match us.stream {
						&mut Some(ref stream) => {
							let mut actions = Vec::with_capacity(post_coinbase_txn.len() + 1);
							actions.push(WeakBlockAction::NewTx { tx: network::serialize::serialize(&work.0.coinbase_tx).unwrap() });

							match us.last_weak_block.take() {
								Some(mut last_weak_block) => {
									let mut old_txids_posn = HashMap::with_capacity(last_weak_block.len());
									for (idx, tx) in last_weak_block.drain(..).enumerate() {
										old_txids_posn.insert(tx, idx + 1); // offset by coinbase tx
									}
									for tx in post_coinbase_txn {
										match old_txids_posn.get(tx) {
											None => actions.push(WeakBlockAction::NewTx { tx: tx.clone() }),
											Some(&idx) => actions.push(WeakBlockAction::TakeTx { n: idx as u16 }),
										}
									}
								},
								None => {
									for tx in post_coinbase_txn {
										actions.push(WeakBlockAction::NewTx { tx: tx.clone() });
									}
								}
							}
							*us.last_weak_block = Some(post_coinbase_txn.clone());
							match stream.unbounded_send(PoolMessage::WeakBlock {
								sketch: WeakBlock {
									header_version: work.0.header_version,
									header_prevblock: template.header_prevblock.clone(),
									header_time: work.0.header_time,
									header_nbits: template.header_nbits,
									header_nonce: work.0.header_nonce,
									merkle_rhss: template.merkle_rhss.clone(),
									user_tag_1: work.0.user_tag.clone(),
									user_tag_2: Vec::new(),
									extra_block_data: extra_block_data.clone(),
									txn: actions,
								},
							}) {
								Ok(_) => { println!("Submitted weak block!"); },
								Err(_) => {
									//TODO: We should queue these for sending later
									println!("Failed to submit weak block as pool connection lost");
								},
							}
						},
						&mut None => {
							//TODO: We should queue these for sending later
							println!("Failed to submit weak block as pool connection lost");
						}
					}
				}
			} else {
				println!("Got share but failed to submit because its not associated with a known user (or we don't have difficulty info for that user yet)!");
			}
		} else {
			println!("Got share but failed to submit because pool has not yet provided user payout information!");
		}
	}
}

impl ConnectionHandler<PoolMessage> for Arc<PoolHandler> {
	type Stream = mpsc::UnboundedReceiver<PoolMessage>;
	type Framer = PoolMsgFramer;

	fn new_connection(&self) -> (PoolMsgFramer, mpsc::UnboundedReceiver<PoolMessage>) {
		let mut us = self.state.write().unwrap();

		let (mut tx, rx) = mpsc::unbounded();
		match tx.start_send(PoolMessage::ProtocolSupport {
			max_version: 1,
			min_version: 1,
			flags: 0,
		}) {
			Ok(_) => {
				us.stream = Some(tx);
			},
			Err(_) => { println!("Pool disconnected before we could send version handshake"); },
		}

		us.last_weak_block = None;
		us.coinbase_postfix_len = None;
		us.cur_payout_info = None;
		(PoolMsgFramer::new(), rx)
	}

	fn connection_closed(&self) {
		let mut us = self.state.write().unwrap();
		us.stream = None;
		let _ = us.job_stream.start_send(PoolProviderAction::ProviderDisconnected);
	}

	fn handle_message(&self, msg: PoolMessage) -> Result<(), io::Error> {
		let mut us = self.state.write().unwrap();
		if us.stream.is_none() { return Ok(()); }

		macro_rules! check_msg_sig {
			($msg_type: expr, $msg: expr, $signature: expr) => {
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

					match us.auth_key {
						Some(pubkey) => match self.secp_ctx.verify(&hash, &$signature, &pubkey) {
							Ok(()) => {},
							Err(_) => return Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError))
						},
						None => return Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError))
					}
				}
			}
		}

		macro_rules! check_msg_timestamp {
			($msg: expr, $msg_type_str: expr) => {
				let time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
				let timestamp = time.as_secs() * 1000 + time.subsec_nanos() as u64 / 1_000_000;
				if $msg.timestamp < timestamp - 1000*60*20 || $msg.timestamp > timestamp + 1000*60*1 {
					println!("Got {} with unreasonable timestamp ({}, our time is {})", $msg_type_str, $msg.timestamp, timestamp);
					return Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError));
				}
			}
		}

		match msg {
			PoolMessage::ProtocolSupport { .. } => {
				println!("Received ProtocolSupport");
				return Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError));
			},
			PoolMessage::ProtocolVersion { selected_version, flags, ref auth_key } => {
				if selected_version != 1 {
					return Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError));
				}
				if flags != 0 {
					return Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError));
				}
				if us.auth_key.is_none() {
					us.auth_key = Some(auth_key.clone());
				} else {
					if us.auth_key.unwrap() != *auth_key {
						println!("Got unexpected auth key");
						return Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError));
					}
				}
				println!("Received ProtocolVersion, using version {}", selected_version);

				for user_auth in us.users_to_reauth.iter() {
					match us.stream.as_ref().unwrap().start_send(PoolMessage::UserAuth { info: user_auth.clone() }) {
						Ok(_) => {},
						Err(_) => {
							return Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError));
						}
					}
				}
			},
			PoolMessage::PayoutInfo { signature, payout_info } => {
				check_msg_sig!(13, payout_info, signature);
				check_msg_timestamp!(payout_info, "PayoutInfo");

				if !payout_info.appended_outputs.is_empty() {
					//TODO: We really should support this
					println!("We don't yet support sending ADDITIONAL_COINBASE_LENGTH messages, and pool provided a multi-output payout info! Dropping pool");
					return Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError));
				}

				if us.cur_payout_info.is_none() || us.cur_payout_info.as_ref().unwrap().timestamp < payout_info.timestamp {
					match us.job_stream.start_send(PoolProviderAction::PoolUpdate {
						info: PoolProviderJob {
							payout_info: payout_info.clone(),
							provider: self.clone(),
						}
					}) {
						Ok(_) => {},
						Err(_) => {
							println!("Pool updating payout info too quickly");
							return Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError));
						}
					}
					println!("Received new payout info!");
					us.cur_payout_info = Some(payout_info);
				}
			},
			PoolMessage::UserAuth { .. } => {
				println!("Received UserAuth?");
				return Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError));
			},
			PoolMessage::AcceptUserAuth { signature, info } => {
				check_msg_sig!(15, info, signature);
				check_msg_timestamp!(info, "AcceptUserAuth");

				if info.coinbase_postfix.len() > 42 {
					println!("Pool sent accept_user_auth coinbase_postfix larger than 42 bytes");
					return Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError));
				}

				if let Some(postfix_len) = us.coinbase_postfix_len {
					if info.coinbase_postfix.len() != postfix_len as usize {
						println!("Pool sent accept_user_auth coinbase_postfix length not equal to previous accept_user_auths");
						return Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError));
					}
				} else {
					us.coinbase_postfix_len = Some(info.coinbase_postfix.len() as u8);
				}

				let refs = us.borrow_mut();
				match refs.user_id_to_postfix.get_mut(&info.user_id) {
					Some(&mut (ref mut last_timestamp, ref mut last_postfix, _)) => {
						if *last_timestamp < info.timestamp {
							let cur_difficulty = if *last_timestamp != 0 {
								refs.coinbase_postfix_to_difficulty.remove(last_postfix)
							} else { None };
							if let &Some(ref difficulty) = &cur_difficulty {
								match refs.job_stream.start_send(PoolProviderAction::UserUpdate {
									user_id: info.user_id.clone(),
									update: PoolProviderUserJob {
										coinbase_postfix: info.coinbase_postfix.clone(),
										target: utils::max_le(difficulty.share_target.clone(), difficulty.weak_block_target.clone()),
									}
								}) {
									Ok(_) => {},
									Err(_) => {
										println!("Pool updating user payout info too quickly");
										return Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError));
									}
								}
							}
							println!("Received new user payout info!");
							*last_timestamp = info.timestamp;
							*last_postfix = info.coinbase_postfix.clone();
							if let Some(difficulty) = cur_difficulty {
								refs.coinbase_postfix_to_difficulty.insert(info.coinbase_postfix, difficulty);
							}
						}
					},
					None => {
						println!("Got AcceptUserAuth for un-auth'ed user?");
						return Ok(());
					}
				}
			},
			PoolMessage::RejectUserAuth { user_id } => {
				match us.job_stream.start_send(PoolProviderAction::UserReject { user_id }) {
					Ok(_) => {},
					Err(_) => {
						println!("Pool updating user rejections too quickly");
						return Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError));
					}
				}
			},
			PoolMessage::DropUser { .. } => {
				println!("Received DropUser?");
				return Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError));
			},
			PoolMessage::ShareDifficulty { difficulty } => {
				check_msg_timestamp!(difficulty, "ShareDifficulty");

				let refs = us.borrow_mut();
				match refs.user_id_to_postfix.get(&difficulty.user_id) {
					Some(&(ref last_timestamp, ref last_postfix, _)) => {
						if *last_timestamp != 0 {
							let entry = refs.coinbase_postfix_to_difficulty.entry(last_postfix.clone());
							match entry {
								hash_map::Entry::Occupied(ref e) => {
									if e.get().timestamp >= difficulty.timestamp { return Ok(()); }
								},
								hash_map::Entry::Vacant(_) => {},
							}
							match refs.job_stream.start_send(PoolProviderAction::UserUpdate {
								user_id: difficulty.user_id.clone(),
								update: PoolProviderUserJob {
									coinbase_postfix: last_postfix.clone(),
									target: utils::max_le(difficulty.share_target.clone(), difficulty.weak_block_target.clone()),
								}
							}) {
								Ok(_) => {},
								Err(_) => {
									println!("Pool updating user difficulty info too quickly");
									return Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError));
								}
							}
							println!("Received new user difficulty!");
							match entry {
								hash_map::Entry::Occupied(mut e) => {
									*e.get_mut() = difficulty;
								},
								hash_map::Entry::Vacant(e) => {
									e.insert(difficulty);
								},
							}
						}
					},
					None => {
						println!("Got ShareDifficulty for un-auth'ed user?");
						return Ok(());
					}
				}
			},
			PoolMessage::Share { .. } => {
				println!("Received Share?");
				return Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError));
			},
			PoolMessage::WeakBlock { .. } => {
				println!("Received WeakBlock?");
				return Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError));
			},
			PoolMessage::WeakBlockStateReset { } => {
				println!("Received WeakBlockStateReset");
				us.last_weak_block = None;
			},
			PoolMessage::ShareAccepted { .. } => {
				println!("Share ACCEPTED!");
				return Ok(());
			},
			PoolMessage::ShareRejected { .. } => {
				println!("Share REJECTED!");
				return Ok(());
			},
			PoolMessage::NewPoolServer { .. } => {
				unimplemented!();
			},
			PoolMessage::VendorMessage { .. } => {
				println!("Got vendor message");
				return Ok(());
			},
		}
		Ok(())
	}
}

struct PoolProviderHolder {
	is_connected: bool,
	last_job: Option<PoolProviderJob>,
	last_user_job: Option<PoolProviderUserJob>,
}

pub struct MultiPoolProvider {
	cur_pool: usize,
	pools: Vec<PoolProviderHolder>,
	job_tx: mpsc::UnboundedSender<PoolProviderUserWork>,
}

pub struct PoolInfo {
	pub host_port: String,
	pub user_id: Vec<u8>,
	pub user_auth: Vec<u8>,
}

pub struct PoolProviderUserWork {
	pub payout_info: PoolProviderJob,
	pub user_payout_info: PoolProviderUserJob,
}

impl MultiPoolProvider {
	pub fn create(mut pool_hosts: Vec<PoolInfo>) -> mpsc::UnboundedReceiver<PoolProviderUserWork> {
		let (job_tx, job_rx) = mpsc::unbounded();
		let cur_work_rc = Arc::new(Mutex::new(MultiPoolProvider {
			cur_pool: std::usize::MAX,
			pools: Vec::with_capacity(pool_hosts.len()),
			job_tx: job_tx,
		}));

		tokio::spawn(future::lazy(move || -> Result<(), ()> {
			for (idx, pool) in pool_hosts.drain(..).enumerate() {
				let (mut auth_write, auth_read) = mpsc::channel(5);
				let (mut handler, mut pool_rx) = PoolHandler::new(None, auth_read);
				auth_write.start_send(PoolAuthAction::AuthUser(PoolUserAuth {
					suggested_target: [0xff; 32],
					minimum_target: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0], // Diff 1
					user_id: pool.user_id,
					user_auth: pool.user_auth,
				})).unwrap();
				cur_work_rc.lock().unwrap().pools.push(PoolProviderHolder {
					is_connected: false,
					last_job: None,
					last_user_job: None,
				});

				let work_rc = cur_work_rc.clone();
				tokio::spawn(pool_rx.for_each(move |job| {
					let mut cur_work = work_rc.lock().unwrap();
					macro_rules! provider_disconnect {
						() => {
							if cur_work.pools[idx].is_connected {
								cur_work.pools[idx].is_connected = false;
								if cur_work.cur_pool == idx {
									// Prefer pools which are connected, then follow the order they
									// were provided in...
									let mut lowest_with_work = std::usize::MAX;
									for (iter_idx, pool) in cur_work.pools.iter().enumerate() {
										if pool.last_job.is_some() && pool.last_user_job.is_some() {
											if pool.is_connected {
												lowest_with_work = iter_idx;
												break;
											} else {
												lowest_with_work = cmp::min(lowest_with_work, iter_idx);
											}
										}
									}
									if lowest_with_work != std::usize::MAX {
										let msg = {
											let new_pool = &cur_work.pools[lowest_with_work];
											PoolProviderUserWork {
												payout_info: new_pool.last_job.as_ref().unwrap().clone(),
												user_payout_info: new_pool.last_user_job.as_ref().unwrap().clone(),
											}
										};
										cur_work.job_tx.start_send(msg).unwrap();
									}
								}
							}
						}
					}
					match job {
						PoolProviderAction::UserUpdate { update, .. } => {
							cur_work.pools[idx].is_connected = true;
							if cur_work.cur_pool >= idx && cur_work.pools[idx].last_job.is_some() {
								cur_work.cur_pool = idx;
								let payout_info = cur_work.pools[idx].last_job.as_ref().unwrap().clone();
								cur_work.job_tx.start_send(PoolProviderUserWork {
									payout_info,
									user_payout_info: update.clone(),
								}).unwrap();
							}
							cur_work.pools[idx].last_user_job = Some(update);
						},
						PoolProviderAction::PoolUpdate { info } => {
							cur_work.pools[idx].is_connected = true;
							if cur_work.cur_pool >= idx && cur_work.pools[idx].last_user_job.is_some() {
								cur_work.cur_pool = idx;
								let user_payout_info = cur_work.pools[idx].last_user_job.as_ref().unwrap().clone();
								cur_work.job_tx.start_send(PoolProviderUserWork {
									payout_info: info.clone(),
									user_payout_info,
								}).unwrap();
							}
							cur_work.pools[idx].last_job = Some(info);
						},
						PoolProviderAction::UserReject { .. } => provider_disconnect!(),
						PoolProviderAction::ProviderDisconnected => provider_disconnect!(),
					}
					Ok(())
				}).then(|_| {
					Ok(())
				}));
				ConnectionMaintainer::new(pool.host_port, handler).make_connection();
			}

			Ok(())
		}));

		job_rx
	}
}
