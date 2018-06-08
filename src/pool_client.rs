use connection_maintainer::*;
use msg_framing::*;
use utils;

use futures::sync::mpsc;

use bitcoin::blockdata::transaction::Transaction;
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
use std::{cmp, io};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone)]
pub struct PoolProviderJob {
	pub payout_info: PoolPayoutInfo,
	pub difficulty: PoolDifficulty,
	pub provider: Arc<PoolHandler>,
}

pub enum PoolProviderAction {
	ProviderDisconnected,
	PoolUpdate { pool: PoolProviderJob },
}

struct PoolHandlerState {
	stream: Option<mpsc::UnboundedSender<PoolMessage>>,
	auth_key: Option<PublicKey>,

	user_id: Vec<u8>,
	user_auth: Vec<u8>,

	cur_payout_info: Option<PoolPayoutInfo>,
	cur_difficulty: Option<PoolDifficulty>,

	last_header_sent: [u8; 32],
	last_weak_block: Option<Vec<(Transaction, Sha256dHash)>>,

	job_stream: mpsc::Sender<PoolProviderAction>,
}

pub struct PoolHandler {
	state: RwLock<PoolHandlerState>,
	secp_ctx: Secp256k1,
}

impl PoolHandler {
	fn new(expected_auth_key: Option<PublicKey>, user_id: Vec<u8>, user_auth: Vec<u8>) -> (Arc<PoolHandler>, mpsc::Receiver<PoolProviderAction>) {
		let (work_sender, work_receiver) = mpsc::channel(5);

		(Arc::new(PoolHandler {
			state: RwLock::new(PoolHandlerState {
				stream: None,
				auth_key: expected_auth_key,

				user_id,
				user_auth,

				cur_payout_info: None,
				cur_difficulty: None,

				last_header_sent: [0; 32],
				last_weak_block: None,

				job_stream: work_sender,
			}),
			secp_ctx: Secp256k1::new(),
		}), work_receiver)
	}

	pub fn send_nonce(&self, work: &(WinningNonce, Sha256dHash), template: &Arc<BlockTemplate>, post_coinbase_txn: &Vec<(Transaction, Sha256dHash)>, prev_header: &BlockHeader) {
		let mut us = self.state.write().unwrap();

		let previous_header = if us.last_header_sent == template.header_prevblock { None } else {
			us.last_header_sent = template.header_prevblock.clone();
			Some(prev_header.clone())
		};

		match us.cur_difficulty {
			Some(ref difficulty) => {
				if utils::does_hash_meet_target(&work.1[..], &difficulty.share_target[..]) {
					match us.stream {
						Some(ref stream) => {
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
								Err(_) => { println!("Failed to submit nonce as pool connection lost"); },
							}
						},
						None => {
							//TODO: We should queue these for sending later
							println!("Failed to submit nonce as pool connection lost");
						}
					}
				}
				if utils::does_hash_meet_target(&work.1[..], &difficulty.weak_block_target[..]) {
					match us.stream {
						Some(ref stream) => {
							let mut actions = Vec::with_capacity(post_coinbase_txn.len() + 1);
							actions.push(WeakBlockAction::NewTx { tx: work.0.coinbase_tx.clone() });

							match us.last_weak_block {
								Some(ref last_weak_block) => {
									let mut old_txids_posn = HashMap::with_capacity(last_weak_block.len());
									for (idx, &(_, ref txid)) in last_weak_block.iter().enumerate() {
										old_txids_posn.insert(txid.clone(), idx + 1); // offset by coinbase tx
									}
									for &(ref tx, ref txid) in post_coinbase_txn {
										match old_txids_posn.get(txid) {
											None => actions.push(WeakBlockAction::NewTx { tx: tx.clone() }),
											Some(&idx) => actions.push(WeakBlockAction::TakeTx { n: idx as u16 }),
										}
									}
								},
								None => {
									for &(ref tx, _) in post_coinbase_txn {
										actions.push(WeakBlockAction::NewTx { tx: tx.clone() });
									}
								}
							}
							match stream.unbounded_send(PoolMessage::WeakBlock {
								sketch: WeakBlock {
									header_version: work.0.header_version,
									header_prevblock: template.header_prevblock.clone(),
									header_time: work.0.header_time,
									header_nbits: template.header_nbits,
									header_nonce: work.0.header_nonce,
									user_tag_1: work.0.user_tag.clone(),
									user_tag_2: Vec::new(),
									txn: actions,
								},
							}) {
								Ok(_) => { println!("Submitted weak block!"); },
								Err(_) => {
									//TODO: We should queue these for sending later
									println!("Failed to submit weak block as pool connection lost");
									return;
								},
							}
						},
						None => {
							//TODO: We should queue these for sending later
							println!("Failed to submit weak block as pool connection lost");
							return;
						}
					}
				} else { return; }
			},
			None => {
				println!("Got share but failed to submit because pool has not yet provided difficulty information!");
				return;
			}
		}
		us.last_weak_block = Some(post_coinbase_txn.clone());
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

				match us.stream.as_ref().unwrap().start_send(PoolMessage::GetPayoutInfo {
					suggested_target: [0xff; 32],
					minimum_target: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0], // Diff 1
					user_id: us.user_id.clone(),
					user_auth: us.user_auth.clone(),
				}) {
					Ok(_) => {},
					Err(_) => {
						return Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError));
					}
				}
			},
			PoolMessage::GetPayoutInfo { .. } => {
				println!("Received GetPayoutInfo?");
				return Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError));
			},
			PoolMessage::PayoutInfo { signature, payout_info } => {
				check_msg_sig!(14, payout_info, signature);

				let time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
				let timestamp = time.as_secs() * 1000 + time.subsec_nanos() as u64 / 1_000_000;
				if payout_info.timestamp < timestamp - 1000*60*20 || payout_info.timestamp > timestamp + 1000*60*1 {
					println!("Got payout_info with unreasonable timestamp ({}, our time is {})", payout_info.timestamp, timestamp);
					return Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError));
				}

				if payout_info.coinbase_postfix.len() > 50 {
					println!("Pool sent payout_info larger than 50 bytes");
					return Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError));
				}

				if us.cur_payout_info.is_none() || us.cur_payout_info.as_ref().unwrap().timestamp < payout_info.timestamp {
					println!("Received new payout info!");
					if us.cur_difficulty.is_some() {
						let cur_difficulty = us.cur_difficulty.clone();
						match us.job_stream.start_send(PoolProviderAction::PoolUpdate {
							pool: PoolProviderJob {
								payout_info: payout_info.clone(),
								difficulty: cur_difficulty.unwrap(),
								provider: self.clone(),
							}
						}) {
							Ok(_) => {},
							Err(_) => {
								println!("Pool updating payout info too quickly");
								return Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError));
							}
						}
					}
					us.cur_payout_info = Some(payout_info);
				}
			},
			PoolMessage::RejectUserAuth { .. } => {
				println!("Received RejectUserAuth for single-user connection, pool should have disconnected us, but either way, auth must be bad.");
				return Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError));
			},
			PoolMessage::DropUser { .. } => {
				println!("Received DropUser?");
				return Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError));
			},
			PoolMessage::ShareDifficulty { difficulty, .. } => {
				let time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
				let timestamp = time.as_secs() * 1000 + time.subsec_nanos() as u64 / 1_000_000;
				if difficulty.timestamp < timestamp - 1000*60*20 || difficulty.timestamp > timestamp + 1000*60*1 {
					println!("Got ShareDifficulty with unreasonable timestamp ({}, our time is {})", difficulty.timestamp, timestamp);
					return Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError));
				}

				if us.cur_difficulty.is_none() || us.cur_difficulty.as_ref().unwrap().timestamp < difficulty.timestamp {
					println!("Received new difficulty!");
					us.cur_difficulty = Some(difficulty);
					if us.cur_payout_info.is_some() {
						let cur_difficulty = us.cur_difficulty.as_ref().unwrap().clone();
						let payout_info = us.cur_payout_info.as_ref().unwrap().clone();
						match us.job_stream.start_send(PoolProviderAction::PoolUpdate {
							pool: PoolProviderJob {
								payout_info,
								difficulty: cur_difficulty,
								provider: self.clone(),
							}
						}) {
							Ok(_) => {},
							Err(_) => {
								println!("Pool updating difficulty too quickly");
								return Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError));
							}
						}
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
}

pub struct MultiPoolProvider {
	cur_pool: usize,
	pools: Vec<PoolProviderHolder>,
	job_tx: mpsc::UnboundedSender<PoolProviderJob>,
}

pub struct PoolInfo {
	pub host_port: String,
	pub user_id: Vec<u8>,
	pub user_auth: Vec<u8>,
}

impl MultiPoolProvider {
	pub fn create(mut pool_hosts: Vec<PoolInfo>) -> mpsc::UnboundedReceiver<PoolProviderJob> {
		let (job_tx, job_rx) = mpsc::unbounded();
		let cur_work_rc = Arc::new(Mutex::new(MultiPoolProvider {
			cur_pool: std::usize::MAX,
			pools: Vec::with_capacity(pool_hosts.len()),
			job_tx: job_tx,
		}));

		tokio::spawn(future::lazy(move || -> Result<(), ()> {
			for (idx, pool) in pool_hosts.drain(..).enumerate() {
				let (mut handler, mut pool_rx) = PoolHandler::new(None, pool.user_id, pool.user_auth);
				cur_work_rc.lock().unwrap().pools.push(PoolProviderHolder {
					is_connected: false,
					last_job: None,
				});

				let work_rc = cur_work_rc.clone();
				tokio::spawn(pool_rx.for_each(move |job| {
					let mut cur_work = work_rc.lock().unwrap();
					match job {
						PoolProviderAction::PoolUpdate { pool } => {
							cur_work.pools[idx].is_connected = true;
							if cur_work.cur_pool >= idx {
								cur_work.cur_pool = idx;
								cur_work.job_tx.start_send(pool.clone()).unwrap();
							}
							cur_work.pools[idx].last_job = Some(pool);
						},
						PoolProviderAction::ProviderDisconnected => {
							if cur_work.pools[idx].is_connected {
								cur_work.pools[idx].is_connected = false;
								if cur_work.cur_pool == idx {
									// Prefer pools which are connected, then follow the order they
									// were provided in...
									let mut lowest_with_work = std::usize::MAX;
									for (iter_idx, pool) in cur_work.pools.iter().enumerate() {
										if pool.last_job.is_some() {
											if pool.is_connected {
												lowest_with_work = iter_idx;
												break;
											} else {
												lowest_with_work = cmp::min(lowest_with_work, iter_idx);
											}
										}
									}
									if lowest_with_work != std::usize::MAX {
										let new_pool = cur_work.pools[lowest_with_work].last_job.as_ref().unwrap().clone();
										cur_work.job_tx.start_send(new_pool).unwrap();
									}
								}
							}
						},
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
