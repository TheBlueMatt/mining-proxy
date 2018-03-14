use msg_framing::{CoinbasePrefixPostfix,WorkInfo,WorkMessage,WorkMsgFramer};
use utils;

use bytes;
use bytes::BufMut;

use crypto::digest::Digest;
use crypto::sha2::Sha256;

use futures::{future,Stream,Sink};
use futures::future::Future;

use tokio::executor::current_thread;
use tokio::net;

use tokio_io::AsyncRead;

use secp256k1::key::{SecretKey,PublicKey};
use secp256k1::Secp256k1;
use secp256k1;

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::io;
use std::rc::Rc;

use futures::unsync::mpsc;

#[derive(Debug)]
struct HandleError;
impl fmt::Display for HandleError {
	fn fmt(&self, fmt: &mut fmt::Formatter) -> Result<(), fmt::Error> {
		fmt.write_str("Failed to handle message")
	}
}
impl Error for HandleError {
	fn description(&self) -> &str {
		"Failed to handle message"
	}
}

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
	// TODO: Limit size of jobs by evicting old ones
	jobs: BTreeMap<u64, WorkInfo>,
}

macro_rules! sign_message {
	($msg: expr, $msg_type: expr, $server_ref: expr) => {
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

			$server_ref.secp_ctx.sign(&hash, &$server_ref.auth_key).unwrap()
		}
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
		current_thread::spawn(job_providers.for_each(move |job| {
			let mut self_ref = us_cp.borrow_mut();
			let our_template_sig = sign_message!(job.template, 3, self_ref);

			self_ref.clients.retain(|ref it| {
				let mut client = it.borrow_mut();
				if !client.handshake_complete { return true; }
				if client.use_header_variants {
					//TODO
					false
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

			self_ref.jobs.insert(job.template.template_id, job);
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
						Err(_) => return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, HandleError)))
					}
				}
			}
			match msg {
				WorkMessage::ProtocolSupport { max_version, min_version, flags } => {
					if min_version > 1 || max_version < 1 {
						return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, HandleError)));
					}
					if (flags & 0b11) == 0 {
						// We don't support clients setting their own payout information
						return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, HandleError)));
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
						let prefix_postfix = CoinbasePrefixPostfix {
							timestamp: 0, //TODO
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
					return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, HandleError)));
				},
				WorkMessage::BlockTemplate { .. } => {
					println!("Received BlockTemplate?");
					return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, HandleError)));
				},
				WorkMessage::WinningNonce { .. } => {
					//TODO
					println!("Received WinningNonce?");
					return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, HandleError)));
				},
				WorkMessage::TransactionDataRequest { .. } => {
					//TODO
					println!("Received TransactionDataRequest?");
					return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, HandleError)));
				},
				WorkMessage::TransactionData { .. } => {
					println!("Received TransactionData?");
					return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, HandleError)));
				},
				WorkMessage::CoinbasePrefixPostfix { .. } => {
					println!("Received CoinbasePrefixPostfix?");
					return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, HandleError)));
				},
				WorkMessage::BlockTemplateHeader { .. } => {
					println!("Received BlockTemplateHeader?");
					return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, HandleError)));
				},
				WorkMessage::WinningNonceHeader { .. } => {
					//TODO
					println!("Received WinningNonceHeader?");
					return future::result(Err(io::Error::new(io::ErrorKind::InvalidData, HandleError)));
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
