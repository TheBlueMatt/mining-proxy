use connection_maintainer::*;
use msg_framing::*;
use utils;

use futures::sync::{mpsc,oneshot};

use bitcoin::blockdata::block::BlockHeader;
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::network::serialize::BitcoinHash;
use bitcoin::util::hash::Sha256dHash;

use bytes;
use bytes::BufMut;

use futures::future;
use futures::{Future,Sink};

use tokio;

use crypto::digest::Digest;
use crypto::sha2::Sha256;

use secp256k1;
use secp256k1::key::PublicKey;
use secp256k1::Secp256k1;

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// A future, essentially
pub struct EventualTxData {
	// We dont really want Fn here, we want FnOnce, but we can't because that'd require a move of
	// the function onto stack, which is of unknown size, so we cant...
	callees: Mutex<Vec<Box<Fn(&Vec<(Transaction, Sha256dHash)>, &BlockHeader) + Send>>>,
	value: RwLock<Option<(Vec<(Transaction, Sha256dHash)>, BlockHeader)>>,
}
impl EventualTxData {
	fn new() -> (Arc<Self>, oneshot::Sender<TransactionData>) {
		let us = Arc::new(Self {
			callees: Mutex::new(Vec::new()),
			value: RwLock::new(None),
		});
		let (tx, rx) = oneshot::channel();
		let us_rx = us.clone();
		tokio::spawn(rx.and_then(move |mut res: TransactionData| {
			let mut value = Vec::with_capacity(res.transactions.len());
			for tx in res.transactions.drain(..) {
				let hash = tx.bitcoin_hash();
				value.push((tx, hash));
			}
			*us_rx.value.write().unwrap() = Some((value, res.previous_header));
			let v_lock = us_rx.value.read().unwrap();
			let v = v_lock.as_ref().unwrap();
			for callee in us_rx.callees.lock().unwrap().iter() {
				(callee)(&v.0, &v.1);
			}
			us_rx.callees.lock().unwrap().clear();
			future::result(Ok(()))
		}).then(|_| {
			future::result(Ok(()))
		}));
		(us, tx)
	}

	pub fn get_and<F: Fn(&Vec<(Transaction, Sha256dHash)>, &BlockHeader) + 'static + Send>(&self, then: F) {
		let value = self.value.read().unwrap();
		match &(*value) {
			&Some(ref value) => {
				then(&value.0, &value.1);
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
	job_stream: mpsc::Sender<(BlockTemplate, Option<CoinbasePrefixPostfix>, Arc<EventualTxData>)>,
}

pub struct JobProviderHandler {
	state: Mutex<JobProviderState>,
	secp_ctx: Secp256k1,
}

impl JobProviderHandler {
	pub fn new(expected_auth_key: Option<PublicKey>) -> (Arc<JobProviderHandler>, mpsc::Receiver<(BlockTemplate, Option<CoinbasePrefixPostfix>, Arc<EventualTxData>)>) {
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

	pub fn send_nonce(&self, work: WinningNonce) {
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
			Err(_) => { println!("Job Provider disconnected before we could send version handshake"); },
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
			WorkMessage::AdditionalCoinbaseLength { .. } => {
				println!("Received AdditionalCoinbaseLength?");
				return Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError));
			},
			WorkMessage::BlockTemplate { signature, template } => {
				check_msg_sig!(4, template, signature);

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
					let (txn, txn_tx) = EventualTxData::new();
					match us.stream.as_ref().unwrap().unbounded_send(WorkMessage::TransactionDataRequest { template_timestamp: template.template_timestamp }) {
						Ok(_) => {},
						Err(_) => return Ok(()), // Disconnected
					}
					let cur_postfix_prefix = us.cur_prefix_postfix.clone();
					match us.job_stream.start_send((template.clone(), cur_postfix_prefix.clone(), txn)) {
						Ok(_) => {},
						Err(_) => {
							println!("Job provider sending jobs too quickly");
							return Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError));
						}
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
				check_msg_sig!(7, data, signature);

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
				check_msg_sig!(8, coinbase_prefix_postfix, signature);

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

						let (txn, txn_tx) = EventualTxData::new();
						//TODO: This is pretty lazy...we should cache these instead of requesting
						//new ones from the server...hopefully they dont update the coinbase prefix
						//postfix very often...
						match us.stream.as_ref().unwrap().unbounded_send(WorkMessage::TransactionDataRequest { template_timestamp: template.template_timestamp }) {
							Ok(_) => {},
							Err(_) => return Ok(()), // Disconnected
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
			WorkMessage::NewWorkServer { .. } => {
				unimplemented!();
			},
			WorkMessage::VendorMessage { .. } => {
				println!("Got vendor message");
				return Ok(());
			},
		}
		Ok(())
	}
}
