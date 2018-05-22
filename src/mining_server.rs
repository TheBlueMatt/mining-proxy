use msg_framing::{BlockTemplate,BlockTemplateHeader,CoinbasePrefixPostfix,WinningNonce,WorkInfo,WorkMessage,WorkMsgFramer};
use utils
;
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
use futures::unsync::mpsc;

use tokio::executor::current_thread;
use tokio::net;

use tokio_io::AsyncRead;

use tokio_timer;

use secp256k1::key::{SecretKey,PublicKey};
use secp256k1::Secp256k1;
use secp256k1;

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io;
use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH, Duration, Instant};

struct MiningClient {
	stream: mpsc::Sender<WorkMessage>,
	client_id: u64,
	use_header_variants: bool,
	handshake_complete: bool,
}

pub struct MiningServer {
	secp_ctx: Secp256k1,
	auth_key: SecretKey,

	clients: Vec<Rc<RefCell<MiningClient>>>,
	client_id_max: u64,
	jobs: BTreeMap<u64, WorkInfo>,
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
	pub fn new(job_providers: mpsc::Receiver<WorkInfo>, auth_key: SecretKey) -> Rc<RefCell<Self>> {
		let us = Rc::new(RefCell::new(Self {
			secp_ctx: Secp256k1::new(),
			auth_key: auth_key,

			clients: Vec::new(),
			client_id_max: 0,
			jobs: BTreeMap::new(),
		}));

		let us_cp = us.clone();
		//This is dumb, but passing the borrow checker otherwise seems hard:
		let second_secp_ctx = Secp256k1::new();
		let auth_key_copy = auth_key;
		current_thread::spawn(job_providers.for_each(move |job| {
			let mut self_ref = us_cp.borrow_mut();
			let our_template_sig = sign_message!(job.template, 3, self_ref);

			self_ref.clients.retain(|ref it| {
				let mut client = it.borrow_mut();
				if !client.handshake_complete { return true; }
				if client.use_header_variants {
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
					match client.stream.start_send(WorkMessage::BlockTemplateHeader {
						signature: sign_message_ctx!(template_header, 8, second_secp_ctx, auth_key_copy),
						template: template_header,
					}) {
						Ok(_) => true,
						Err(_) => false
					}
				} else {
					match client.stream.start_send(WorkMessage::BlockTemplate {
						signature: our_template_sig.clone(),
						template: (*job.template).clone(),
					}) {
						Ok(_) => true,
						Err(_) => false
					}
				}
			});

			self_ref.jobs.insert(job.template.template_timestamp, job);
			future::result(Ok(()))
		}));

		let us_timer = us.clone(); // Wait, you wanted a deconstructor? LOL
		current_thread::spawn(tokio_timer::Interval::new(Instant::now() + Duration::from_secs(10), Duration::from_secs(15)).for_each(move |_| {
			let time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
			let timestamp = (time.as_secs() - 30) * 1000 + time.subsec_nanos() as u64 / 1_000_000;

			let mut r = us_timer.borrow_mut();
			loop {
				// There should be a much easier way to implement this...
				let first_timestamp = match r.jobs.iter().next() {
					Some((k, _)) => *k,
					None => break,
				};
				if first_timestamp < timestamp {
					r.jobs.remove(&first_timestamp);
				}
			}

			future::result(Ok(()))
		}).then(|_| {
			future::result(Ok(()))
		}));

		us
	}

	pub fn new_connection(rc: Rc<RefCell<Self>>, stream: net::TcpStream) {
		stream.set_nodelay(true).unwrap();

		let (tx, rx) = stream.framed(WorkMsgFramer::new()).split();

		let client_ref = {
			let (send_sink, send_stream) = mpsc::channel(5);
			current_thread::spawn(tx.send_all(send_stream.map_err(|_| -> io::Error {
				panic!("mpsc streams cant generate errors!");
			})).then(|_| {
				future::result(Ok(()))
			}));

			let mut us = rc.borrow_mut();
			let client = Rc::new(RefCell::new(MiningClient {
				stream: send_sink,
				client_id: us.client_id_max,
				use_header_variants: false,
				handshake_complete: false,
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

		current_thread::spawn(rx.for_each(move |msg| -> future::FutureResult<(), io::Error> {
			let mut client = client_ref.borrow_mut();
			macro_rules! send_response {
				($msg: expr) => {
					match client.stream.start_send($msg) {
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
					client.use_header_variants = (flags & 0b11) == 0b11;
					client.handshake_complete = true;
					let us = rc.borrow();
					send_response!(WorkMessage::ProtocolVersion {
						selected_version: 1,
						flags: if (flags & 0b11) == 0b11 { 0b11 } else { 0b01 },
						auth_key: PublicKey::from_secret_key(&us.secp_ctx, &us.auth_key).unwrap(),
					});
					if !client.use_header_variants {
						let time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
						let prefix_postfix = CoinbasePrefixPostfix {
							timestamp: time.as_secs() * 1000 + time.subsec_nanos() as u64 / 1_000_000,
							coinbase_prefix_postfix: utils::le64_to_array(client.client_id).to_vec(),
						};

						send_response!(WorkMessage::CoinbasePrefixPostfix {
							signature: sign_message!(prefix_postfix, 7, us),
							coinbase_prefix_postfix: prefix_postfix,
						});
					}
					match rc.borrow().jobs.iter().last() { //TODO: This is ineffecient, map should have a last()
						Some(job) => {
							send_response!(WorkMessage::BlockTemplate {
								signature: sign_message!(job.1.template, 3, us),
								template: (*job.1.template).clone(),
							});
						}, None => {}
					}
				},
				WorkMessage::ProtocolVersion { .. } => {
					println!("Received ProtocolVersion?");
					return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError)));
				},
				WorkMessage::BlockTemplate { .. } => {
					println!("Received BlockTemplate?");
					return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, utils::HandleError)));
				},
				WorkMessage::WinningNonce { nonces } => {
					match rc.borrow().jobs.get(&nonces.template_timestamp) {
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
								match job.solutions.unbounded_send(Rc::new((nonces, block_hash))) {
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
					match rc.borrow().jobs.get(&template_timestamp) {
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
								match job.solutions.unbounded_send(Rc::new((WinningNonce {
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
			}
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
