extern crate bitcoin;
extern crate bytes;
extern crate futures;
extern crate tokio;
extern crate tokio_io;
extern crate tokio_codec;
extern crate crypto;
extern crate secp256k1;

#[macro_use]
extern crate serde_json;

mod msg_framing;

mod stratum_server;
use stratum_server::*;

mod utils;

mod work_getter;
use work_getter::*;

mod connection_maintainer;
use connection_maintainer::*;

mod pool_client;
use pool_client::*;

mod work_client;
use work_client::*;

use futures::future;
use futures::sync::mpsc;
use futures::{Future,Stream,Sink};

use tokio::net;

use std::env;
use std::sync::{Arc, Mutex};
use std::net::ToSocketAddrs;

struct CurrentWork {
	cur_work: Option<WorkProviderJob>,
	cur_pool_work: Option<PoolProviderJob>,
}

fn main() {
	println!("USAGE: pool-proxy (--job_provider=host:port)* --pool_server=host:port --stratum_listen_bind=IP:port");
	println!("A stratum proxy for a number of different user clients against one pool");
	println!("--job_provider - bitcoind(s) running as mining server(s) to get work from");
	println!("--pool_server - pool server(s) to get payout address from/submit shares to");
	println!("--stratum_listen_bind - the address to bind to to announce stratum jobs on");
	println!("We always try to keep exactly one connection open per argument, no matter how");
	println!("many hosts a DNS name may resolve to. We try each hostname until one works.");
	println!("Job providers are not prioritized (the latest job is always used)");

	let mut job_provider_hosts = Vec::new();
	let mut pool_server_host = None;
	let mut stratum_listen_bind = None;

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
			if pool_server_host.is_some() {
				println!("Cannot specify multiple pool servers");
				return;
			}
			match arg.split_at(14).1.to_socket_addrs() {
				Err(_) => {
					println!("Bad address resolution: {}", arg);
					return;
				},
				Ok(_) => pool_server_host = Some(arg.split_at(14).1.to_string()),
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
		} else {
			println!("Unkown arg: {}", arg);
			return;
		}
	}

	if job_provider_hosts.is_empty() {
		println!("Need at least some job providers");
		return;
	}
	if pool_server_host.is_none() {
		println!("Need at least a pool server");
		return;
	}
	if stratum_listen_bind.is_none() {
		println!("Need some stratum listen bind");
		return;
	}

	let mut rt = tokio::runtime::Runtime::new().unwrap();
	rt.spawn(future::lazy(move || -> Result<(), ()> {
		let cur_work = Arc::new(Mutex::new(CurrentWork {
			cur_work: None,
			cur_pool_work: None,
		}));
		let (mut job_sender, job_receiver) = mpsc::unbounded();
		let (mut user_sender, user_receiver) = mpsc::unbounded();

		let cur_work_job = cur_work.clone();
		let mut job_sender_job = job_sender.clone();
		tokio::spawn(MultiJobProvider::create(job_provider_hosts).for_each(move |work_update| {
			let mut state = cur_work_job.lock().unwrap();
			state.cur_work = Some(work_update);
			if let &Some(ref pool_info) = &state.cur_pool_work {
				if let Some(work) = merge_job_pool(&None, state.cur_work.as_ref().unwrap(), Some(pool_info), None) {
					job_sender_job.start_send(work).unwrap();
				}
			}
			Ok(())
		}));
		let (auth_write, auth_read) = mpsc::channel(25);
		let (pool_handler, pool_rx) = PoolHandler::new(None, auth_read);
		ConnectionMaintainer::new(pool_server_host.unwrap(), pool_handler).make_connection();

		tokio::spawn(pool_rx.for_each(move |action| {
			match action {
				PoolProviderAction::ProviderDisconnected => {
					println!("WARNING: POOL DISCONNECTED!");
					println!("This is going to cause a major bandwidth spike and probably some lost shares!");
					println!("Please investigate sending the connection over a more reliable proxy, eg over a VPN.");
					println!("This is probably also an indication that you should investigate loss rates and");
					println!("latency on the link, which may be cause some share rejections/higher orphan rate");
				},
				PoolProviderAction::PoolUpdate { info } => {
					let mut state = cur_work.lock().unwrap();
					state.cur_pool_work = Some(info);
					if let &Some(ref work_info) = &state.cur_work {
						if let Some(work) = merge_job_pool(&None, work_info, Some(state.cur_pool_work.as_ref().unwrap()), None) {
							job_sender.start_send(work).unwrap();
						}
					}
				},
				PoolProviderAction::UserUpdate { user_id, update } => {
					user_sender.start_send(UserUpdate::WorkUpdate { user_id, user_info: update }).unwrap();
				},
				PoolProviderAction::UserReject { user_id } => {
					user_sender.start_send(UserUpdate::DropUser { user_id }).unwrap();
				},
			}
			Ok(())
		}));

		let server = StratumServer::new(job_receiver, Some((user_receiver, auth_write)));
		match net::TcpListener::bind(&stratum_listen_bind.unwrap()) {
			Ok(listener) => {
				tokio::spawn(listener.incoming().for_each(move |sock| {
					StratumServer::new_connection(server.clone(), sock);
					Ok(())
				}).then(|_| {
					Ok(())
				}));
			},
			Err(_) => {
				panic!("Failed to bind to listen bind addr");
			}
		}
		Ok(())
	}));
	rt.shutdown_on_idle().wait().unwrap();
}
