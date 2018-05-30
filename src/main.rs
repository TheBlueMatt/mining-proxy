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

mod stratum_server;
use stratum_server::*;

mod mining_server;
use mining_server::*;

mod utils;

mod work_getter;
use work_getter::*;

use bitcoin::util::address::Address;
use bitcoin::util::privkey;

use futures::future;
use futures::sync::mpsc;
use futures::{Future,Stream,Sink};

use tokio::net;

use std::{env};
use std::net::ToSocketAddrs;
use std::str::FromStr;

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

	let mut pools = Vec::with_capacity(pool_server_hosts.len());
	for pool in pool_server_hosts.drain(..) {
		pools.push(PoolInfo {
			host_port: pool,
			user_id: user_id.as_ref().unwrap().clone(),
			user_auth: user_auth.as_ref().unwrap().clone(),
		});
	}

	let mut rt = tokio::runtime::Runtime::new().unwrap();
	rt.spawn(future::lazy(move || -> Result<(), ()> {
		let job_rx = WorkGetter::create(job_provider_hosts, pools, payout_addr.clone().unwrap().script_pubkey());

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
