extern crate bitcoin;
extern crate bytes;
extern crate futures;
extern crate tokio;
extern crate tokio_io;
extern crate crypto;
extern crate secp256k1;

#[macro_use]
extern crate serde_json;

mod msg_framing;
use msg_framing::*;

mod stratum_server;
use stratum_server::*;

mod mining_server;
use mining_server::*;

mod utils;

use bitcoin::blockdata::transaction::{TxOut,Transaction};
use bitcoin::blockdata::script::Script;
use bitcoin::util::address::Address;
use bitcoin::util::privkey;
use bitcoin::util::hash::Sha256dHash;

use bytes::BufMut;

use futures::future;
use futures::sync::{mpsc,oneshot};
use futures::{Future,Stream,Sink};

use tokio::{net, timer};

use tokio_io::{AsyncRead,codec};

use crypto::digest::Digest;
use crypto::sha2::Sha256;

use secp256k1::key::PublicKey;
use secp256k1::Secp256k1;

use std::collections::HashMap;
use std::{env,io,marker};
use std::net::{SocketAddr,ToSocketAddrs};
use std::sync::{Arc, Mutex, RwLock};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH, Duration, Instant};

/// A future, essentially
struct Eventual<Value> {
	// We dont really want Fn here, we want FnOnce, but we can't because that'd require a move of
	// the function onto stack, which is of unknown size, so we cant...
	callees: Mutex<Vec<Box<Fn(&Value) + Send>>>,
	value: RwLock<Option<Value>>,
}
impl<Value: 'static + Send + Sync> Eventual<Value> {
	fn new() -> (Arc<Self>, oneshot::Sender<Value>) {
		let us = Arc::new(Self {
			callees: Mutex::new(Vec::new()),
			value: RwLock::new(None),
		});
		let (tx, rx) = oneshot::channel();
		let us_rx = us.clone();
		tokio::spawn(rx.and_then(move |res| {
			*us_rx.value.write().unwrap() = Some(res);
			let v_lock = us_rx.value.read().unwrap();
			let v = v_lock.as_ref().unwrap();
			for callee in us_rx.callees.lock().unwrap().iter() {
				(callee)(v);
			}
			us_rx.callees.lock().unwrap().clear();
			future::result(Ok(()))
		}).then(|_| {
			future::result(Ok(()))
		}));
		(us, tx)
	}

	fn get_and<F: Fn(&Value) + 'static + Send>(&self, then: F) {
		let value = self.value.read().unwrap();
		match &(*value) {
			&Some(ref value) => {
				then(value);
				return;
			},
			&None => {
				self.callees.lock().unwrap().push(Box::new(then));
			},
		}
	}
}

struct JobProviderState {
	stream: Option<mpsc::UnboundedSender<WorkMessage>>,
	auth_key: Option<PublicKey>,

	cur_template: Option<BlockTemplate>,
	cur_prefix_postfix: Option<CoinbasePrefixPostfix>,

	pending_tx_data_requests: HashMap<u64, oneshot::Sender<TransactionData>>,
	job_stream: mpsc::Sender<(BlockTemplate, Option<CoinbasePrefixPostfix>, Arc<Eventual<TransactionData>>)>,
}

pub struct JobProviderHandler {
	state: Mutex<JobProviderState>,
	secp_ctx: Secp256k1,
}

impl JobProviderHandler {
	fn new(expected_auth_key: Option<PublicKey>) -> (Arc<JobProviderHandler>, mpsc::Receiver<(BlockTemplate, Option<CoinbasePrefixPostfix>, Arc<Eventual<TransactionData>>)>) {
		let (work_sender, work_receiver) = mpsc::channel(10);

		(Arc::new(JobProviderHandler {
			state: Mutex::new(JobProviderState {
				stream: None,
				auth_key: expected_auth_key,

				cur_template: None,
				cur_prefix_postfix: None,

				pending_tx_data_requests: HashMap::new(),
				job_stream: work_sender,
			}),
			secp_ctx: Secp256k1::new(),
		}), work_receiver)
	}

	fn send_nonce(&self, work: WinningNonce) {
		let state = self.state.lock().unwrap();
		match &state.stream {
			&Some(ref stream) => {
				match stream.unbounded_send(WorkMessage::WinningNonce {
					nonces: work
				}) {
					Ok(_) => { println!("Submitted job-matching (ie full-block) nonce!"); },
					Err(_) => { println!("Failed to submit job-matching (ie full-block) nonce as job provider disconnected"); }
				}
			},
			&None => {
				println!("Failed to submit job-matching (ie full-block) nonce!");
			}
		}
	}
}

impl ConnectionHandler<WorkMessage> for Arc<JobProviderHandler> {
	type Stream = mpsc::UnboundedReceiver<WorkMessage>;
	type Framer = WorkMsgFramer;

	fn new_connection(&self) -> (WorkMsgFramer, mpsc::UnboundedReceiver<WorkMessage>) {
		let (mut tx, rx) = mpsc::unbounded();
		match tx.start_send(WorkMessage::ProtocolSupport {
			max_version: 1,
			min_version: 1,
			flags: 0,
		}) {
			Ok(_) => {
				self.state.lock().unwrap().stream = Some(tx);
			},
			Err(_) => { panic!("Cant fail to send first message on an unbounded stream"); },
		}
		(WorkMsgFramer::new(), rx)
	}

	fn connection_closed(&self) {
		self.state.lock().unwrap().stream = None;
	}

	fn handle_message(&self, msg: WorkMessage) -> Result<(), io::Error> {
		let mut us = self.state.lock().unwrap();
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
			WorkMessage::ProtocolSupport { .. } => {
				println!("Received ProtocolSupport");
				return Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError));
			},
			WorkMessage::ProtocolVersion { selected_version, flags, ref auth_key } => {
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
			},
			WorkMessage::BlockTemplate { signature, template } => {
				check_msg_sig!(3, template, signature);

				let time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
				let timestamp = time.as_secs() * 1000 + time.subsec_nanos() as u64 / 1_000_000;
				if template.template_timestamp < timestamp - 1000*60*20 || template.template_timestamp > timestamp + 1000*60*1 {
					println!("Got template with unreasonable timestamp ({}, our time is {})", template.template_timestamp, timestamp);
					return Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError));
				}

				if !template.coinbase_postfix.is_empty() || template.coinbase_prefix.len() > 42 {
					println!("Invalid non-final BlockTemplate from work provider");
					return Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError));
				}
				match us.cur_prefix_postfix {
					Some(ref prefix_postfix) => {
						if prefix_postfix.coinbase_prefix_postfix.len() + template.coinbase_prefix.len() > 42 {
							println!("Invalid non-final BlockTemplate + CoinbasePrefixPostfix from work provider");
							return Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError));
						}
					},
					None => {}
				}

				if us.cur_template.is_none() || us.cur_template.as_ref().unwrap().template_timestamp < template.template_timestamp {
					println!("Received new BlockTemplate with diff lower bound {}", utils::target_to_diff_lb(&template.target));
					let (txn, txn_tx) = Eventual::new();
					let cur_postfix_prefix = us.cur_prefix_postfix.clone();
					match us.job_stream.start_send((template.clone(), cur_postfix_prefix.clone(), txn)) {
						Ok(_) => {},
						Err(_) => {
							println!("Job provider sending jobs too quickly");
							return Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError));
						}
					}
					match us.stream.as_ref().unwrap().unbounded_send(WorkMessage::TransactionDataRequest { template_timestamp: template.template_timestamp }) {
						Ok(_) => {},
						Err(_) => { panic!("unbounded streams should never fail"); }
					}
					us.pending_tx_data_requests.insert(template.template_timestamp, txn_tx);
					us.cur_template = Some(template);
				}
			},
			WorkMessage::WinningNonce { .. } => {
				println!("Received WinningNonce?");
				return Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError));
			},
			WorkMessage::TransactionDataRequest { .. } => {
				println!("Received TransactionDataRequest?");
				return Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError));
			},
			WorkMessage::TransactionData { signature, data } => {
				check_msg_sig!(6, data, signature);

				match us.pending_tx_data_requests.remove(&data.template_timestamp) {
					Some(chan) => {
						match chan.send(data) {
							Ok(()) => {},
							Err(_) => {
								println!("We gave up on job before job provider sent us transactions");
							}
						}
					},
					None => {
						println!("Received unknown TransactionData?");
					}
				}
			},
			WorkMessage::CoinbasePrefixPostfix { signature, coinbase_prefix_postfix } => {
				check_msg_sig!(7, coinbase_prefix_postfix, signature);

				let time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
				let timestamp = time.as_secs() * 1000 + time.subsec_nanos() as u64 / 1_000_000;
				if coinbase_prefix_postfix.timestamp < timestamp - 1000*60*20 || coinbase_prefix_postfix.timestamp > timestamp + 1000*60*1 {
					println!("Got coinbase_prefix_postfix with unreasonable timestamp ({}, our time is {})", coinbase_prefix_postfix.timestamp, timestamp);
					return Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError));
				}

				match us.cur_template {
					Some(ref template) => {
						if coinbase_prefix_postfix.coinbase_prefix_postfix.len() + template.coinbase_prefix.len() > 42 {
							println!("Invalid non-final CoinbasePrefixPostfix + BlockTemplate from work provider");
							return Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError));
						}
					},
					None => {
						if coinbase_prefix_postfix.coinbase_prefix_postfix.len() > 42 {
							println!("Invalid non-final CoinbasePrefixPostfix from work provider");
							return Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError));
						}
					}
				}

				if us.cur_prefix_postfix.is_none() || us.cur_prefix_postfix.as_ref().unwrap().timestamp < coinbase_prefix_postfix.timestamp {
					println!("Received new CoinbasePrefixPostfix");
					us.cur_prefix_postfix = Some(coinbase_prefix_postfix);
					if us.cur_template.is_some() {
						let cur_prefix_postfix = us.cur_prefix_postfix.clone();
						let template = us.cur_template.as_ref().unwrap().clone();

						let (txn, txn_tx) = Eventual::new();
						//TODO: This is pretty lazy...we should cache these instead of requesting
						//new ones from the server...hopefully they dont update the coinbase prefix
						//postfix very often...
						match us.stream.as_ref().unwrap().unbounded_send(WorkMessage::TransactionDataRequest { template_timestamp: template.template_timestamp }) {
							Ok(_) => {},
							Err(_) => { panic!("unbounded streams should never fail"); }
						}
						us.pending_tx_data_requests.insert(template.template_timestamp, txn_tx);

						match us.job_stream.start_send((template, cur_prefix_postfix, txn)) {
							Ok(_) => {},
							Err(_) => {
								println!("Job provider sending jobs too quickly");
								return Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError));
							}
						}
					}
				}
			},
			WorkMessage::BlockTemplateHeader { .. } => {
				println!("Received BlockTemplateHeader?");
				return Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError));
			},
			WorkMessage::WinningNonceHeader { .. } => {
				println!("Received WinningNonceHeader?");
				return Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError));
			},
		}
		Ok(())
	}
}

struct PoolHandlerState {
	pool_priority: usize,
	stream: Option<mpsc::UnboundedSender<PoolMessage>>,
	auth_key: Option<PublicKey>,

	user_id: Vec<u8>,
	user_auth: Vec<u8>,

	cur_payout_info: Option<PoolPayoutInfo>,
	cur_difficulty: Option<PoolDifficulty>,
	last_weak_block: Option<Vec<Transaction>>,

	job_stream: mpsc::Sender<(PoolPayoutInfo, Option<PoolDifficulty>)>,
}

struct PoolHandler {
	state: Mutex<PoolHandlerState>,
	secp_ctx: Secp256k1,
}

impl PoolHandler {
	fn new(expected_auth_key: Option<PublicKey>, user_id: Vec<u8>, user_auth: Vec<u8>, pool_priority: usize) -> (Arc<PoolHandler>, mpsc::Receiver<(PoolPayoutInfo, Option<PoolDifficulty>)>) {
		let (work_sender, work_receiver) = mpsc::channel(5);

		(Arc::new(PoolHandler {
			state: Mutex::new(PoolHandlerState {
				pool_priority: pool_priority,
				stream: None,
				auth_key: expected_auth_key,

				user_id,
				user_auth,

				cur_payout_info: None,
				cur_difficulty: None,
				last_weak_block: None,

				job_stream: work_sender,
			}),
			secp_ctx: Secp256k1::new(),
		}), work_receiver)
	}

	fn is_connected(&self) -> bool {
		self.state.lock().unwrap().stream.is_some()
	}

	fn get_priority(&self) -> usize {
		self.state.lock().unwrap().pool_priority
	}

	fn send_nonce(&self, work: &(WinningNonce, Sha256dHash), template: &Arc<BlockTemplate>, post_coinbase_txn: &Vec<Transaction>) {
		let us = self.state.lock().unwrap();
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
									user_tag: work.0.user_tag.clone(),
								}
							}) {
								Ok(_) => { println!("Submitted share!"); },
								Err(_) => { println!("Failed to submit nonce as pool connection lost"); },
							}
						},
						None => {
							println!("Failed to submit nonce as pool connection lost");
						}
					}
				}
				if utils::does_hash_meet_target(&work.1[..], &difficulty.weak_block_target[..]) {
					match us.last_weak_block {
						Some(ref last_weak_block) => {
							//TODO
						},
						None => {
							//TODO
						},
					}
				}
			},
			None => {
				println!("Got share but failed to submit because pool has not yet provided difficulty information!");
			}
		}
	}
}

impl ConnectionHandler<PoolMessage> for Arc<PoolHandler> {
	type Stream = mpsc::UnboundedReceiver<PoolMessage>;
	type Framer = PoolMsgFramer;

	fn new_connection(&self) -> (PoolMsgFramer, mpsc::UnboundedReceiver<PoolMessage>) {
		let mut us = self.state.lock().unwrap();

		let (mut tx, rx) = mpsc::unbounded();
		match tx.start_send(PoolMessage::ProtocolSupport {
			max_version: 1,
			min_version: 1,
			flags: 0,
		}) {
			Ok(_) => {
				us.stream = Some(tx);
			},
			Err(_) => { panic!("Cant fail to send first message on an unbounded stream"); },
		}

		us.last_weak_block = None;
		(PoolMsgFramer::new(), rx)
	}

	fn connection_closed(&self) {
		self.state.lock().unwrap().stream = None;
	}

	fn handle_message(&self, msg: PoolMessage) -> Result<(), io::Error> {
		let mut us = self.state.lock().unwrap();
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
				check_msg_sig!(11, payout_info, signature);

				let time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
				let timestamp = time.as_secs() * 1000 + time.subsec_nanos() as u64 / 1_000_000;
				if payout_info.timestamp < timestamp - 1000*60*20 || payout_info.timestamp > timestamp + 1000*60*1 {
					println!("Got payout_info with unreasonable timestamp ({}, our time is {})", payout_info.timestamp, timestamp);
					return Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError));
				}

				if payout_info.coinbase_postfix.len() > 42 {
					println!("Pool sent payout_info larger than 42 bytes");
					return Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError));
				}

				if us.cur_payout_info.is_none() || us.cur_payout_info.as_ref().unwrap().timestamp < payout_info.timestamp {
					println!("Received new payout info!");
					let cur_difficulty = us.cur_difficulty.clone();
					match us.job_stream.start_send((payout_info.clone(), cur_difficulty.clone())) {
						Ok(_) => {},
						Err(_) => {
							println!("Pool updating payout info too quickly");
							return Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError));
						}
					}
					us.cur_payout_info = Some(payout_info);
				}
			},
			PoolMessage::ShareDifficulty { signature, difficulty } => {
				check_msg_sig!(12, difficulty, signature);

				println!("Received new difficulty!");
				us.cur_difficulty = Some(difficulty);
				if us.cur_payout_info.is_some() {
					let cur_difficulty = us.cur_difficulty.clone();
					let payout_info = us.cur_payout_info.as_ref().unwrap().clone();
					match us.job_stream.start_send((payout_info, cur_difficulty)) {
						Ok(_) => {},
						Err(_) => {
							println!("Pool updating difficulty too quickly");
							return Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError));
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
			PoolMessage::NewPoolServer { .. } => {
				unimplemented!();
			},
		}
		Ok(())
	}
}

fn merge_job_pool(our_payout_script: Script, job_info: &Option<(BlockTemplate, Option<CoinbasePrefixPostfix>, Arc<Eventual<TransactionData>>)>, job_source: Option<Arc<JobProviderHandler>>, payout_info: &Option<(PoolPayoutInfo, Option<PoolDifficulty>)>, payout_source: Option<Arc<PoolHandler>>) -> Option<WorkInfo> {
	match job_info {
		&Some((ref template_ref, ref coinbase_prefix_postfix, ref tx_data)) => {
			let mut template = template_ref.clone();

			let mut outputs = Vec::with_capacity(template.appended_coinbase_outputs.len() + 2);
			let mut constant_value_output = 0;
			for output in template.appended_coinbase_outputs.iter() {
				if output.value > 21000000*100000000 {
					return None;
				}
				constant_value_output += output.value;
			}

			match coinbase_prefix_postfix {
				&Some(ref postfix) => {
					template.coinbase_prefix.extend_from_slice(&postfix.coinbase_prefix_postfix[..]);
				},
				&None => {}
			}

			if template.coinbase_value_remaining <= 0 {
				return None;
			}

			let work_target = template.target.clone();

			match payout_info {
				&Some((ref info, ref difficulty)) => {
					for output in info.appended_outputs.iter() {
						if output.value > 21000000*100000000 {
							return None;
						}
						constant_value_output += output.value;
					}

					let value_remaining = (template.coinbase_value_remaining as i64) - (constant_value_output as i64);
					if value_remaining <= 0 {
						return None;
					}

					outputs.push(TxOut {
						value: value_remaining as u64,
						script_pubkey: info.remaining_payout.clone(),
					});

					outputs.extend_from_slice(&info.appended_outputs[..]);

					match difficulty {
						&Some(ref pool_diff) => {
							template.target = utils::max_le(template.target, pool_diff.share_target);
							template.target = utils::max_le(template.target, pool_diff.weak_block_target);
						},
						&None => {}
					}

					if !template.coinbase_postfix.is_empty() { panic!("We should have checked this on the recv end!"); }
					template.coinbase_postfix.extend_from_slice(&info.coinbase_postfix[..]);
				},
				&None => {
					outputs.push(TxOut {
						value: template.coinbase_value_remaining,
						script_pubkey: our_payout_script,
					});
				}
			}

			outputs.extend_from_slice(&template.appended_coinbase_outputs[..]);

			template.appended_coinbase_outputs = outputs;

			let template_rc = Arc::new(template);

			let (solution_tx, solution_rx) = mpsc::unbounded();
			let tx_data_ref = tx_data.clone();
			let template_ref = template_rc.clone();
			tokio::spawn(solution_rx.for_each(move |nonces: Arc<(WinningNonce, Sha256dHash)>| {
				match job_source {
					Some(ref source) => {
						if utils::does_hash_meet_target(&nonces.1[..], &work_target[..]) {
							source.send_nonce(nonces.0.clone());
						}
					},
					None => {}
				}
				match payout_source {
					Some(ref source) => {
						let source_ref = source.clone();
						let template_ref_2 = template_ref.clone();
						tx_data_ref.get_and(move |txn| {
							let source_clone = source_ref.clone();
							source_clone.send_nonce(&nonces, &template_ref_2, &txn.transactions);
						});
					},
					None => {}
				}
				future::result(Ok(()))
			}).then(|_| {
				future::result(Ok(()))
			}));

			Some(WorkInfo {
				template: template_rc,
				solutions: solution_tx
			})
		},
		&None => None
	}
}

pub trait ConnectionHandler<MessageType> {
	type Stream : Stream<Item = MessageType> + Send;
	type Framer : codec::Encoder<Item = MessageType, Error = io::Error> + codec::Decoder<Item = MessageType, Error = io::Error> + Send;
	fn new_connection(&self) -> (Self::Framer, Self::Stream);
	fn handle_message(&self, msg: MessageType) -> Result<(), io::Error>;
	fn connection_closed(&self);
}

pub struct ConnectionMaintainer<MessageType: 'static + Send, HandlerProvider : ConnectionHandler<MessageType>> {
	host: String,
	cur_addrs: Option<Vec<SocketAddr>>,
	handler: HandlerProvider,
	ph : marker::PhantomData<&'static MessageType>,
}

impl<MessageType : Send + Sync, HandlerProvider : 'static + ConnectionHandler<MessageType> + Send + Sync> ConnectionMaintainer<MessageType, HandlerProvider> {
	pub fn new(host: String, handler: HandlerProvider) -> ConnectionMaintainer<MessageType, HandlerProvider> {
		ConnectionMaintainer {
			host: host,
			cur_addrs: None,
			handler: handler,
			ph: marker::PhantomData,
		}
	}

	pub fn make_connection(mut self) {
		if {
			if self.cur_addrs.is_none() {
				//TODO: Resolve async
				match self.host.to_socket_addrs() {
					Err(_) => {
						true
					},
					Ok(addrs) => {
						self.cur_addrs = Some(addrs.collect());
						false
					}
				}
			} else { false }
		} {
			tokio::spawn(timer::Delay::new(Instant::now() + Duration::from_secs(10)).then(move |_| -> future::FutureResult<(), ()> {
				self.make_connection();
				future::result(Ok(()))
			}));
			return;
		}

		let addr_option = {
			let addr = self.cur_addrs.as_mut().unwrap().pop();
			if addr.is_none() {
				self.cur_addrs = None;
			}
			addr
		};

		match addr_option {
			Some(addr) => {
				println!("Trying connection to {}", addr);

				tokio::spawn(net::TcpStream::connect(&addr).then(move |res| -> future::FutureResult<(), ()> {
					match res {
						Ok(stream) => {
							println!("Connected to {}!", stream.peer_addr().unwrap());
							stream.set_nodelay(true).unwrap();

							let (framer, tx_stream) = self.handler.new_connection();
							let (tx, rx) = stream.framed(framer).split();
							let stream = tx_stream.map_err(|_| -> io::Error {
								panic!("mpsc streams cant generate errors!");
							});
							tokio::spawn(tx.send_all(stream).then(|_| {
								println!("Disconnected on send side, will reconnect...");
								future::result(Ok(()))
							}));
							let us = Arc::new(self);
							let us_close = us.clone();
							tokio::spawn(rx.for_each(move |msg| {
								future::result(us.handler.handle_message(msg))
							}).then(move |_| {
								println!("Disconnected on recv side, will reconnect...");
								us_close.handler.connection_closed();
								Arc::try_unwrap(us_close).ok().unwrap().make_connection();
								future::result(Ok(()))
							}));
						},
						Err(_) => {
							self.make_connection();
						}
					};
					future::result(Ok(()))
				}));
			},
			None => {
				tokio::spawn(timer::Delay::new(Instant::now() + Duration::from_secs(10)).then(move |_| {
					self.make_connection();
					future::result(Ok(()))
				}));
			},
		}
	}
}

struct JobInfo {
	payout_script: Script,
	cur_job: Option<(BlockTemplate, Option<CoinbasePrefixPostfix>, Arc<Eventual<TransactionData>>)>,
	cur_job_source: Option<Arc<JobProviderHandler>>,
	cur_pool: Option<(PoolPayoutInfo, Option<PoolDifficulty>)>,
	cur_pool_source: Option<Arc<PoolHandler>>,
	job_tx: mpsc::Sender<WorkInfo>,
}

fn main() {
	println!("USAGE: stratum-proxy (--job_provider=host:port)* (--pool_server=host:port)* --stratum_listen_bind=IP:port --mining_listen_bind=IP:port --mining_auth_key=base58privkey --payout_address=addr");
	println!("--job_provider - bitcoind(s) running as mining server(s) to get work from");
	println!("--pool_server - pool server(s) to get payout address from/submit shares to");
	println!("--pool_user_id - user id (eg username) on pool");
	println!("--pool_user_auth - user auth (eg password) on pool");
	println!("--stratum_listen_bind - the address to bind to to announce stratum jobs on");
	println!("--mining_listen_bind - the address to bind to to announce jobs on natively");
	println!("--mining_auth_key - the auth key to use to authenticate to native clients");
	println!("--payout_address - the Bitcoin address on which to receive payment");
	println!("We always try to keep exactly one connection open per argument, no matter how");
	println!("many hosts a DNS name may resolve to. We try each hostname until one works.");
	println!("Job providers are not prioritized (the latest job is always used), pools are");
	println!("prioritized in the order they appear on the command line.");
	println!("--payout_address is used whenever no pools are available but does not affect");
	println!("pool payout information (only --pool_user_id does so).");

	let mut job_provider_hosts = Vec::new();
	let mut pool_server_hosts = Vec::new();
	let mut user_id = None;
	let mut user_auth = None;
	let mut stratum_listen_bind = None;
	let mut mining_listen_bind = None;
	let mut mining_auth_key = None;
	let mut payout_addr = None;

	for arg in env::args().skip(1) {
		if arg.starts_with("--job_provider") {
			match arg.split_at(15).1.to_socket_addrs() {
				Err(_) => {
					println!("Bad address resolution: {}", arg);
					return;
				},
				Ok(_) => job_provider_hosts.push(arg.split_at(15).1.to_string())
			}
		} else if arg.starts_with("--pool_server") {
			match arg.split_at(14).1.to_socket_addrs() {
				Err(_) => {
					println!("Bad address resolution: {}", arg);
					return;
				},
				Ok(_) => pool_server_hosts.push(arg.split_at(14).1.to_string())
			}
		} else if arg.starts_with("--stratum_listen_bind") {
			if stratum_listen_bind.is_some() {
				println!("Cannot specify multiple listen binds");
				return;
			}
			stratum_listen_bind = Some(match arg.split_at(22).1.parse() {
				Ok(sockaddr) => sockaddr,
				Err(_) =>{
					println!("Failed to parse stratum_listen_bind into a socket address");
					return;
				}
			});
		} else if arg.starts_with("--mining_listen_bind") {
			if mining_listen_bind.is_some() {
				println!("Cannot specify multiple listen binds");
				return;
			}
			mining_listen_bind = Some(match arg.split_at(21).1.parse() {
				Ok(sockaddr) => sockaddr,
				Err(_) =>{
					println!("Failed to parse mining_listen_bind into a socket address");
					return;
				}
			});
		} else if arg.starts_with("--mining_auth_key") {
			if mining_auth_key.is_some() {
				println!("Cannot specify multiple auth keys");
				return;
			}
			mining_auth_key = Some(match privkey::Privkey::from_str(arg.split_at(18).1) {
				Ok(privkey) => {
					if !privkey.compressed {
						println!("Private key must represent a compressed key!");
						return;
					}
					privkey.key
				},
				Err(_) =>{
					println!("Failed to parse mining_auth_key into a private key");
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
				Ok(addr) => addr,
				Err(_) => {
					println!("Failed to parse payout_address into a Bitcoin address");
					return;
				}
			});
		} else if arg.starts_with("--pool_user_id") {
			if user_id.is_some() {
				println!("Cannot specify multiple pool_user_ids");
				return;
			}
			user_id = Some(arg.split_at(15).1.as_bytes().to_vec());
		} else if arg.starts_with("--pool_user_auth") {
			if user_auth.is_some() {
				println!("Cannot specify multiple pool_user_auths");
				return;
			}
			user_auth = Some(arg.split_at(17).1.as_bytes().to_vec());
		} else {
			println!("Unkown arg: {}", arg);
			return;
		}
	}

	if job_provider_hosts.is_empty() {
		println!("Need at least some job providers");
		return;
	}
	if stratum_listen_bind.is_none() && mining_listen_bind.is_none() {
		println!("Need some listen bind");
		return;
	}
	if payout_addr.is_none() {
		println!("Need some payout address for fallback/solo mining");
		return;
	}
	if mining_listen_bind.is_some() && mining_auth_key.is_none() {
		println!("Need some mining_auth_key for mining_listen_bind");
		return;
	}

	if user_id.is_none() {
		user_id = Some(Vec::new());
	}
	if user_auth.is_none() {
		user_auth = Some(Vec::new());
	}

	let (job_tx, job_rx) = mpsc::channel(5);
	let cur_work_rc = Arc::new(Mutex::new(JobInfo {
		payout_script: payout_addr.clone().unwrap().script_pubkey(),
		cur_job: None,
		cur_job_source: None,
		cur_pool: None,
		cur_pool_source: None,
		job_tx: job_tx,
	}));

	let mut rt = tokio::runtime::Runtime::new().unwrap();
	rt.spawn(future::lazy(move || -> Result<(), ()> {
		for host in job_provider_hosts {
			let (mut handler, mut job_rx) = JobProviderHandler::new(None);
			let work_rc = cur_work_rc.clone();
			let handler_rc = handler.clone();
			tokio::spawn(job_rx.for_each(move |job| {
				let mut cur_work = work_rc.lock().unwrap();
				if cur_work.cur_job.is_none() || cur_work.cur_job.as_ref().unwrap().0.template_timestamp < job.0.template_timestamp {
					let new_job = Some(job);
					match merge_job_pool(cur_work.payout_script.clone(), &new_job, Some(handler_rc.clone()), &cur_work.cur_pool, cur_work.cur_pool_source.clone()) {
						Some(work) => {
							match cur_work.job_tx.start_send(work) {
								Ok(_) => {},
								Err(_) => {
									println!("Job provider is providing work faster than we can process it");
								}
							}
							cur_work.cur_job = new_job;
							cur_work.cur_job_source = Some(handler_rc.clone());
						},
						None => {}
					}
				}
				Ok(())
			}).then(|_| {
				Ok(())
			}));
			ConnectionMaintainer::new(host, handler).make_connection();
		}

		for (idx, host) in pool_server_hosts.iter().enumerate() {
			let (mut handler, mut pool_rx) = PoolHandler::new(None, user_id.as_ref().unwrap().clone(), user_auth.as_ref().unwrap().clone(), idx);
			let work_rc = cur_work_rc.clone();
			let handler_rc = handler.clone();
			tokio::spawn(pool_rx.for_each(move |pool_info| {
				let mut cur_work = work_rc.lock().unwrap();
				match cur_work.cur_pool_source {
					Some(ref cur_pool) => {
						//TODO: Fallback to lower-priority pool when one gets disconnected
						if cur_pool.is_connected() && cur_pool.get_priority() < handler_rc.get_priority() {
							return Ok(());
						}
					},
					None => {}
				}
				let new_pool = Some(pool_info);
				match merge_job_pool(cur_work.payout_script.clone(), &cur_work.cur_job, cur_work.cur_job_source.clone(), &new_pool, Some(handler_rc.clone())) {
					Some(work) => {
						match cur_work.job_tx.start_send(work) {
							Ok(_) => {},
							Err(_) => {
								println!("Job provider is providing work faster than we can process it");
							}
						}
						cur_work.cur_pool = new_pool;
						cur_work.cur_pool_source = Some(handler_rc.clone());
					},
					None => {
						if cur_work.cur_job.is_none() {
							cur_work.cur_pool = new_pool;
							cur_work.cur_pool_source = Some(handler_rc.clone());
						}
					}
				}
				Ok(())
			}).then(|_| {
				Ok(())
			}));
			ConnectionMaintainer::new(host.clone(), handler).make_connection();
		}

		macro_rules! bind_and_handle {
			($listen_bind_option: expr, $server: expr, $server_type: tt) => {
				match $listen_bind_option {
					Some(listen_bind) => {
						let server = $server;
						match net::TcpListener::bind(&listen_bind) {
							Ok(listener) => {
								tokio::spawn(listener.incoming().for_each(move |sock| {
									$server_type::new_connection(server.clone(), sock);
									Ok(())
								}).then(|_| {
									Ok(())
								}));
							},
							Err(_) => {
								println!("Failed to bind to listen bind addr");
								return Ok(());
							}
						};
					},
					None => {},
				}
			}
		}

		if stratum_listen_bind.is_some() && mining_listen_bind.is_none() {
			bind_and_handle!(stratum_listen_bind, StratumServer::new(job_rx), StratumServer);
		} else if stratum_listen_bind.is_none() && mining_listen_bind.is_some() {
			bind_and_handle!(mining_listen_bind, MiningServer::new(job_rx, mining_auth_key.unwrap()), MiningServer);
		} else {
			let (mut stratum_tx, stratum_rx) = mpsc::channel(5);
			let (mut mining_tx, mining_rx) = mpsc::channel(5);
			tokio::spawn(job_rx.for_each(move |job| {
				match mining_tx.start_send(job.clone()) {
					Ok(_) => {},
					Err(_) => { println!("Dropped new job for native clients as server ran behind!"); },
				}
				match stratum_tx.start_send(job) {
					Ok(_) => {},
					Err(_) => { println!("Dropped new job for stratum clients as server ran behind!"); },
				}
				Ok(())
			}).then(|_| {
				Ok(())
			}));
			bind_and_handle!(stratum_listen_bind, StratumServer::new(stratum_rx), StratumServer);
			bind_and_handle!(mining_listen_bind, MiningServer::new(mining_rx, mining_auth_key.unwrap()), MiningServer);
		}

		Ok(())
	}));
	rt.shutdown_on_idle().wait().unwrap();
}
