use msg_framing::{BlockTemplate,BlockTemplateHeader,CoinbasePrefixPostfix,WinningNonce,WorkMessage,WorkMsgFramer};
use client_utils::WorkInfo;
use utils;

use bitcoin::blockdata::block::BlockHeader;
use bitcoin::blockdata::script::Script;
use bitcoin::blockdata::transaction::{TxIn,Transaction};
use bitcoin::util::hash::Sha256dHash;
use bitcoin::network::serialize::BitcoinHash;

use bytes;
use bytes::BufMut;

use crypto::digest::Digest;
use crypto::sha2::Sha256;

use futures::{future,Stream,Sink};
use futures::future::Future;
use futures::sync::mpsc;

use tokio;
use tokio::{net, timer};

use tokio_io::AsyncRead;

use secp256k1::key::{SecretKey,PublicKey};
use secp256k1::Secp256k1;
use secp256k1;

use std::collections::BTreeMap;
use std::io;
use std::sync::{Arc, Mutex, RwLock};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH, Duration, Instant};

struct MiningClient {
	stream: mpsc::Sender<WorkMessage>,
	client_id: u64,
	use_header_variants: AtomicBool,
	handshake_complete: AtomicBool,
}

pub struct MiningServer {
	secp_ctx: Secp256k1,
	auth_key: SecretKey,

	clients: Mutex<(Vec<Arc<MiningClient>>, u64)>,
	jobs: RwLock<BTreeMap<u64, WorkInfo>>,
}

fn work_to_coinbase_tx(template: &BlockTemplate, client_id: u64) -> Transaction {
	let mut script_sig = template.coinbase_prefix.clone();
	script_sig.extend_from_slice(&utils::le64_to_array(client_id));
	script_sig.extend_from_slice(&template.coinbase_postfix[..]);

	Transaction {
		version: template.coinbase_version,
		input: vec!(TxIn {
			prev_hash: Default::default(),
			prev_index: 0xffffffff,
			script_sig: Script::from(script_sig),
			sequence: template.coinbase_input_sequence,
			witness: vec!(),
		}),
		output: template.appended_coinbase_outputs.clone(),
		lock_time: template.coinbase_locktime,
	}
}

fn work_to_merkle_root(template: &BlockTemplate, coinbase_txid: Sha256dHash) -> [u8; 32] {
	let mut merkle_lhs = [0; 32];
	merkle_lhs.copy_from_slice(&coinbase_txid[..]);
	let mut sha = Sha256::new();
	for rhs in template.merkle_rhss.iter() {
		sha.reset();
		sha.input(&merkle_lhs);
		sha.input(&rhs[..]);
		sha.result(&mut merkle_lhs);
		sha.reset();
		sha.input(&merkle_lhs);
		sha.result(&mut merkle_lhs);
	}
	merkle_lhs
}

macro_rules! sign_message_ctx {
	($msg: expr, $msg_type: expr, $secp_ctx: expr, $auth_key: expr) => {
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

			$secp_ctx.sign(&hash, &$auth_key).unwrap()
		}
	}
}
macro_rules! sign_message {
	($msg: expr, $msg_type: expr, $server_ref: expr) => {
		sign_message_ctx!($msg, $msg_type, $server_ref.secp_ctx, $server_ref.auth_key)
	}
}

impl MiningServer {
	pub fn new(job_providers: mpsc::Receiver<WorkInfo>, auth_key: SecretKey) -> Arc<Self> {
		let us = Arc::new(Self {
			secp_ctx: Secp256k1::new(),
			auth_key: auth_key,

			clients: Mutex::new((Vec::new(), 0)),
			jobs: RwLock::new(BTreeMap::new()),
		});

		let us_cp = us.clone();
		//This is dumb, but passing the borrow checker otherwise seems hard:
		let second_secp_ctx = Secp256k1::new();
		let auth_key_copy = auth_key;
		tokio::spawn(job_providers.for_each(move |job| {
			let our_template_sig = sign_message!(job.template, 4, us_cp);

			{
				let mut jobs = us_cp.jobs.write().unwrap();
				jobs.insert(job.template.template_timestamp, job.clone());
			}

			let clients = us_cp.clients.lock().unwrap().0.clone();
			for client in clients {
				if !client.handshake_complete.load(Ordering::Acquire) { continue; }
				let mut client_stream = client.stream.clone();
				if client.use_header_variants.load(Ordering::Acquire) {
					let template_header = BlockTemplateHeader {
						template_timestamp: job.template.template_timestamp,
						template_variant: client.client_id,
						target: job.template.target,

						header_version: job.template.header_version,
						header_prevblock: job.template.header_prevblock,
						header_merkle_root: work_to_merkle_root(&*job.template, work_to_coinbase_tx(&*job.template, client.client_id).txid()),
						header_time: job.template.header_time,
						header_nbits: job.template.header_nbits,
					};
					let _ = client_stream.start_send(WorkMessage::BlockTemplateHeader {
						signature: sign_message_ctx!(template_header, 9, second_secp_ctx, auth_key_copy),
						template: template_header,
					});
				} else {
					let _ = client_stream.start_send(WorkMessage::BlockTemplate {
						signature: our_template_sig.clone(),
						template: (*job.template).clone(),
					});
				}
			}

			future::result(Ok(()))
		}));

		let us_timer = us.clone(); // Wait, you wanted a deconstructor? LOL
		tokio::spawn(timer::Interval::new(Instant::now() + Duration::from_secs(10), Duration::from_secs(1)).for_each(move |_| {
			let time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
			let timestamp = (time.as_secs() - 30) * 1000 + time.subsec_nanos() as u64 / 1_000_000;

			let mut jobs = us_timer.jobs.write().unwrap();
			while jobs.len() > 1 {
				// There should be a much easier way to implement this...
				let first_timestamp = match jobs.iter().next() {
					Some((k, _)) => *k,
					None => break,
				};
				if first_timestamp < timestamp {
					jobs.remove(&first_timestamp);
				} else { break; }
			}

			future::result(Ok(()))
		}).then(|_| {
			future::result(Ok(()))
		}));

		us
	}

	pub fn new_connection(us: Arc<Self>, stream: net::TcpStream) {
		stream.set_nodelay(true).unwrap();

		let (tx, rx) = stream.framed(WorkMsgFramer::new()).split();

		let (client, mut send_sink) = {
			let (send_sink, send_stream) = mpsc::channel(5);
			tokio::spawn(tx.send_all(send_stream.map_err(|_| -> io::Error {
				panic!("mpsc streams cant generate errors!");
			})).then(|_| {
				future::result(Ok(()))
			}));
			let mut sink_dup = send_sink.clone();

			let mut client_list = us.clients.lock().unwrap();
			let client = Arc::new(MiningClient {
				stream: send_sink,
				client_id: client_list.1,
				use_header_variants: AtomicBool::new(false),
				handshake_complete: AtomicBool::new(false),
			});
			println!("Got new client connection (id {})", client_list.1);
			client_list.1 += 1;

			let client_ref = client.clone();
			client_list.0.push(client);
			(client_ref, sink_dup)
		};

		let client_close = client.clone();
		let us_close = us.clone();

		//TODO: Set a timer for the client to always push *something* to them every 30 seconds or
		//so, as otherwise stratum clients time out.

		tokio::spawn(rx.for_each(move |msg| -> future::FutureResult<(), io::Error> {
			macro_rules! send_response {
				($msg: expr) => {
					match send_sink.start_send($msg) {
						Ok(_) => {},
						Err(_) => return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError)))
					}
				}
			}
			match msg {
				WorkMessage::ProtocolSupport { max_version, min_version, flags } => {
					if min_version > 1 || max_version < 1 {
						return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError)));
					}
					if (flags & 0b11) == 0 {
						// We don't support clients setting their own payout information
						return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError)));
					}
					send_response!(WorkMessage::ProtocolVersion {
						selected_version: 1,
						flags: if (flags & 0b11) == 0b11 { 0b11 } else { 0b01 },
						auth_key: PublicKey::from_secret_key(&us.secp_ctx, &us.auth_key).unwrap(),
					});
					if !client.use_header_variants.load(Ordering::Acquire) {
						let time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
						let prefix_postfix = CoinbasePrefixPostfix {
							timestamp: time.as_secs() * 1000 + time.subsec_nanos() as u64 / 1_000_000,
							coinbase_prefix_postfix: utils::le64_to_array(client.client_id).to_vec(),
						};

						send_response!(WorkMessage::CoinbasePrefixPostfix {
							signature: sign_message!(prefix_postfix, 8, us),
							coinbase_prefix_postfix: prefix_postfix,
						});
					}
					let jobs = us.jobs.read().unwrap();
					match jobs.iter().last() { //TODO: This is ineffecient, map should have a last()
						Some(job) => {
							send_response!(WorkMessage::BlockTemplate {
								signature: sign_message!(job.1.template, 4, us),
								template: (*job.1.template).clone(),
							});
						}, None => {}
					}
					client.use_header_variants.store((flags & 0b11) == 0b11, Ordering::Release);
					client.handshake_complete.store(true, Ordering::Release);
				},
				WorkMessage::ProtocolVersion { .. } => {
					println!("Received ProtocolVersion?");
					return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError)));
				},
				WorkMessage::AdditionalCoinbaseLength { .. } => {
					println!("Received AdditionalCoinbaseLength for final-work client?");
					return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError)));
				},
				WorkMessage::BlockTemplate { .. } => {
					println!("Received BlockTemplate?");
					return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError)));
				},
				WorkMessage::WinningNonce { nonces } => {
					let jobs = us.jobs.read().unwrap();
					match jobs.get(&nonces.template_timestamp) {
						Some(job) => {
							let block_hash = BlockHeader {
								version: nonces.header_version,
								prev_blockhash: Sha256dHash::from(&job.template.header_prevblock[..]),
								merkle_root: Sha256dHash::from(&work_to_merkle_root(&*job.template, nonces.coinbase_tx.txid())[..]),
								time: nonces.header_time,
								bits: job.template.header_nbits,
								nonce: nonces.header_nonce,
							}.bitcoin_hash();

							if utils::does_hash_meet_target(&block_hash[..], &job.template.target[..]) {
								match job.solutions.unbounded_send(Arc::new((nonces, block_hash))) {
									Ok(_) => {},
									Err(_) => { panic!(); },
								};
							} else {
								println!("Got work that missed target (hashed to {}, which is greater than {})", utils::bytes_to_hex(&block_hash[..]), utils::bytes_to_hex(&job.template.target[..]));
							}
						},
						None => {
							println!("Got WinningNonceHeader for unknown job_id");
						}
					}
				},
				WorkMessage::TransactionDataRequest { .. } => {
					//TODO
					println!("Received TransactionDataRequest?");
					return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError)));
				},
				WorkMessage::TransactionData { .. } => {
					println!("Received TransactionData?");
					return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError)));
				},
				WorkMessage::CoinbasePrefixPostfix { .. } => {
					println!("Received CoinbasePrefixPostfix?");
					return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError)));
				},
				WorkMessage::BlockTemplateHeader { .. } => {
					println!("Received BlockTemplateHeader?");
					return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError)));
				},
				WorkMessage::WinningNonceHeader { template_timestamp, template_variant, header_version, header_time, header_nonce, user_tag } => {
					let jobs = us.jobs.read().unwrap();
					match jobs.get(&template_timestamp) {
						Some(job) => {
							let block_hash = BlockHeader {
								version: header_version,
								prev_blockhash: Sha256dHash::from(&job.template.header_prevblock[..]),
								merkle_root: Sha256dHash::from(&work_to_merkle_root(&*job.template, work_to_coinbase_tx(&*job.template, template_variant).txid())[..]),
								time: header_time,
								bits: job.template.header_nbits,
								nonce: header_nonce,
							}.bitcoin_hash();

							if utils::does_hash_meet_target(&block_hash[..], &job.template.target[..]) {
								match job.solutions.unbounded_send(Arc::new((WinningNonce {
									template_timestamp,
									header_version,
									header_time,
									header_nonce,
									user_tag,
									coinbase_tx: work_to_coinbase_tx(&*job.template, template_variant),
								}, block_hash))) {
									Ok(_) => {},
									Err(_) => { panic!(); },
								};
							} else {
								println!("Got work that missed target (hashed to {}, which is greater than {})", utils::bytes_to_hex(&block_hash[..]), utils::bytes_to_hex(&job.template.target[..]));
							}
						},
						None => {
							println!("Got WinningNonceHeader for unknown job_id");
						}
					}
				},
				WorkMessage::NewWorkServer { .. } => {
					println!("Got NewWorkServer?");
					return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError)));
				},
				WorkMessage::VendorMessage { .. } => {
					println!("Got vendor message");
					return future::result(Ok(()));
				},
			}
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
