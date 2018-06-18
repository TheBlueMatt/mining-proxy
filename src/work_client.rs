use connection_maintainer::*;
use msg_framing::*;
use utils;

use futures::sync::{mpsc,oneshot};

use bitcoin::blockdata::block::BlockHeader;

use bytes;
use bytes::BufMut;

use futures::future;
use futures::{Future,Stream,Sink};

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
	callees: Mutex<Vec<Box<Fn(&Vec<Vec<u8>>, &BlockHeader, &Vec<u8>) + Send>>>,
	value: RwLock<Option<(Vec<Vec<u8>>, BlockHeader, Vec<u8>)>>,
}
impl EventualTxData {
	fn new() -> (Arc<Self>, oneshot::Sender<TransactionData>) {
		let us = Arc::new(Self {
			callees: Mutex::new(Vec::new()),
			value: RwLock::new(None),
		});
		let (tx, rx) = oneshot::channel();
		let us_rx = us.clone();
		tokio::spawn(rx.and_then(move |res: TransactionData| {
			*us_rx.value.write().unwrap() = Some((res.transactions, res.previous_header, res.extra_block_data));
			let v_lock = us_rx.value.read().unwrap();
			let v = v_lock.as_ref().unwrap();
			for callee in us_rx.callees.lock().unwrap().iter() {
				(callee)(&v.0, &v.1, &v.2);
			}
			us_rx.callees.lock().unwrap().clear();
			future::result(Ok(()))
		}).then(|_| {
			future::result(Ok(()))
		}));
		(us, tx)
	}

	pub fn get_and<F: Fn(&Vec<Vec<u8>>, &BlockHeader, &Vec<u8>) + 'static + Send>(&self, then: F) {
		let value = self.value.read().unwrap();
		match &(*value) {
			&Some(ref value) => {
				then(&value.0, &value.1, &value.2);
				return;
			},
			&None => {
				self.callees.lock().unwrap().push(Box::new(then));
			},
		}
	}

	pub fn has_result(&self) -> bool {
		self.value.read().unwrap().is_some()
	}
}

#[derive(Clone)]
pub struct WorkProviderJob {
	pub template: BlockTemplate,
	pub coinbase_prefix_postfix: Option<CoinbasePrefixPostfix>,
	pub tx_data: Arc<EventualTxData>,
	pub provider: Arc<JobProviderHandler>,
}

enum WorkProviderAction {
	ProviderDisconnected,
	JobUpdate { job: WorkProviderJob },
}

struct JobProviderState {
	stream: Option<mpsc::UnboundedSender<WorkMessage>>,
	auth_key: Option<PublicKey>,

	cur_template: Option<BlockTemplate>,
	cur_prefix_postfix: Option<CoinbasePrefixPostfix>,

	pending_tx_data_requests: HashMap<u64, oneshot::Sender<TransactionData>>,
	job_stream: mpsc::Sender<WorkProviderAction>,
}

pub struct JobProviderHandler {
	state: Mutex<JobProviderState>,
	secp_ctx: Secp256k1,
}

impl JobProviderHandler {
	fn new(expected_auth_key: Option<PublicKey>) -> (Arc<JobProviderHandler>, mpsc::Receiver<WorkProviderAction>) {
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
		let mut us = self.state.lock().unwrap();
		let _ = us.job_stream.start_send(WorkProviderAction::ProviderDisconnected);
		us.stream = None;
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

				for output in template.appended_coinbase_outputs.iter() {
					if output.value != 0 {
						println!("Invalid non-final BlockTemplate attempted to claim value");
						return Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError));
					}
				}

				if us.cur_template.is_none() || us.cur_template.as_ref().unwrap().template_timestamp < template.template_timestamp {
					println!("Received new BlockTemplate with diff lower bound {}", utils::target_to_diff_lb(&template.target));
					let (txn, txn_tx) = EventualTxData::new();
					match us.stream.as_ref().unwrap().unbounded_send(WorkMessage::TransactionDataRequest { template_timestamp: template.template_timestamp }) {
						Ok(_) => {},
						Err(_) => return Ok(()), // Disconnected
					}
					let cur_postfix_prefix = us.cur_prefix_postfix.clone();
					match us.job_stream.start_send(WorkProviderAction::JobUpdate {
						job: WorkProviderJob {
							template: template.clone(),
							coinbase_prefix_postfix: cur_postfix_prefix.clone(),
							tx_data: txn,
							provider: self.clone(),
						}
					}) {
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

						match us.job_stream.start_send(WorkProviderAction::JobUpdate {
							job: WorkProviderJob {
								template,
								coinbase_prefix_postfix: cur_prefix_postfix,
								tx_data: txn,
								provider: self.clone(),
							}
						}) {
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

struct WorkProviderHolder {
	is_connected: bool,
	last_job: Option<WorkProviderJob>,
}

pub struct MultiJobProvider {
	best_job: u64,
	jobs: Vec<WorkProviderHolder>,
	job_tx: mpsc::UnboundedSender<WorkProviderJob>,
}

impl MultiJobProvider {
	pub fn create(mut job_provider_hosts: Vec<String>) -> mpsc::UnboundedReceiver<WorkProviderJob> {
		let (job_tx, job_rx) = mpsc::unbounded();
		let cur_work_rc = Arc::new(Mutex::new(MultiJobProvider {
			best_job: 0,
			jobs: Vec::with_capacity(job_provider_hosts.len()),
			job_tx: job_tx,
		}));

		tokio::spawn(future::lazy(move || -> Result<(), ()> {
			for (idx, host) in job_provider_hosts.drain(..).enumerate() {
				let (mut handler, mut job_rx) = JobProviderHandler::new(None);
				cur_work_rc.lock().unwrap().jobs.push(WorkProviderHolder {
					is_connected: false,
					last_job: None,
				});

				let work_rc = cur_work_rc.clone();
				tokio::spawn(job_rx.for_each(move |job| {
					let mut cur_work = work_rc.lock().unwrap();
					match job {
						WorkProviderAction::JobUpdate { job } => {
							cur_work.jobs[idx].is_connected = true;
							if cur_work.best_job < job.template.template_timestamp {
								cur_work.best_job = job.template.template_timestamp;
								cur_work.job_tx.start_send(job.clone()).unwrap();
							}
							cur_work.jobs[idx].last_job = Some(job);
						},
						WorkProviderAction::ProviderDisconnected => {
							if cur_work.jobs[idx].is_connected {
								cur_work.jobs[idx].is_connected = false;
								if cur_work.jobs[idx].last_job.is_some() && cur_work.jobs[idx].last_job.as_ref().unwrap().template.template_timestamp == cur_work.best_job {
									cur_work.best_job = 0;

									// Prefer jobs which are from connected providers, then jobs for which we can construct
									// a complete weak block (which the pool could relay for us)...
									let mut highest_timestamp = (0, 0);
									let mut highest_connected_timestamp = (0, 0);
									for (idx, job) in cur_work.jobs.iter().enumerate() {
										if job.last_job.is_some() {
											let job_template = job.last_job.as_ref().unwrap();
											if job_template.tx_data.has_result() && job_template.template.template_timestamp > highest_timestamp.0 {
												highest_timestamp = (job_template.template.template_timestamp, idx);
											}
											if job.is_connected && job_template.template.template_timestamp > highest_connected_timestamp.0 {
												highest_connected_timestamp = (job_template.template.template_timestamp, idx);
											}
										}
									}
									if highest_connected_timestamp.0 != 0 {
										let new_job = cur_work.jobs[highest_connected_timestamp.1].last_job.as_ref().unwrap().clone();
										cur_work.job_tx.start_send(new_job).unwrap();
									} else if highest_timestamp.0 != 0 {
										let new_job = cur_work.jobs[highest_timestamp.1].last_job.as_ref().unwrap().clone();
										cur_work.job_tx.start_send(new_job).unwrap();
									}
								}
							}
						},
					}
					Ok(())
				}).then(|_| {
					Ok(())
				}));
				ConnectionMaintainer::new(host, handler).make_connection();
			}

			Ok(())
		}));

		job_rx
	}
}
