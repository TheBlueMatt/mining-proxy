extern crate bitcoin;
extern crate bytes;
extern crate futures;
extern crate tokio;
extern crate tokio_io;
extern crate tokio_codec;
extern crate crypto;
extern crate secp256k1;
extern crate clap;

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

mod work_info;

mod connection_maintainer;

mod pool_client;
mod work_client;

mod timeout_stream;

use bitcoin::util::address::Address;
use bitcoin::util::privkey;

use futures::future;
use futures::sync::mpsc;
use futures::{Future,Stream,Sink};

use tokio::net;

use std::net::ToSocketAddrs;
use std::str::FromStr;

fn clap_parser_config<'a, 'b>() -> clap::App<'a, 'b> {
	let about = "A stratum/work protocol proxy for a number of ASICs mining on a single user account on a pool or for a solo miner.

We always try to keep exactly one connection open per argument, no matter how many hosts a DNS name may resolve to. \
We try each hostname until one works. Job providers are not prioritized (the latest job is always used), pools are \
prioritized in the order they appear on the command line. --payout_address is used whenever no pools are available \
but does not affect pool payout information (only --pool_user_id does so).";

	clap::App::new("mining-proxy")
		.author(env!("CARGO_PKG_AUTHORS"))
		.about(about)
		.version(env!("CARGO_PKG_VERSION"))

		.arg(clap::Arg::with_name("job_provider")
			.help("bitcoind(s) running as mining server(s) to get work from")
			.long("job-provider")
			.value_name("HOST:PORT")
			.required(true)
			.takes_value(true)
			.multiple(true))

		.arg(clap::Arg::with_name("pool_server")
			.help("pool server(s) to get payout address from/submit shares to")
			.long("pool-server")
			.value_name("HOST:PORT")
			.required(true)
			.takes_value(true)
			.multiple(true))

		.arg(clap::Arg::with_name("pool_user_id")
			.help("user id (eg username) on pool")
			.long("pool-user-id")
			.value_name("POOLID")
			.required(true)
			.takes_value(true))

		.arg(clap::Arg::with_name("pool_user_auth")
			.help("user auth (eg password) on pool")
			.long("pool-user-auth")
			.value_name("POOLAUTH")
			.required(true)
			.takes_value(true))

		.arg(clap::Arg::with_name("stratum_listen_bind")
			.help("Stratum job announcement binding address.")
			.long("stratum-listen-bind")
			.value_name("IP:PORT")
			.required(false)
			.takes_value(true))

		.arg(clap::Arg::with_name("mining_listen_bind")
			.help("the address to bind to to announce jobs on natively")
			.long("mining-listen-bind")
			.value_name("IP:PORT")
			.required(true)
			.takes_value(true))

		.arg(clap::Arg::with_name("mining_auth_key")
			.help("the auth key to use to authenticate to native clients")
			.long("mining-auth-key")
			.value_name("BASE58PRIVKEY")
			.required(false)
			.takes_value(true))

		.arg(clap::Arg::with_name("payout_address")
			.help("the Bitcoin address on which to receive payment")
			.long("payout-address")
			.value_name("ADDR")
			.required(true)
			.takes_value(true))
}

struct CommandLineArgs {
	job_provider_hosts: Vec<String>,
	pools: Vec<PoolInfo>,
	stratum_listen_bind: Option<std::net::SocketAddr>,
	mining_listen_bind: Option<std::net::SocketAddr>,
	mining_auth_key: Option<secp256k1::key::SecretKey>,
	payout_address: bitcoin::util::address::Address
}

fn parse_command_line_arguments() -> Result<CommandLineArgs, String> {
	let arg_matches = clap_parser_config().get_matches();

	let job_provider_hosts: Vec<_>= arg_matches
        .values_of("job_provider")
        .unwrap()
        .map(String::from)
        .collect();
	if let Err(err) = check_socket_addresses(&job_provider_hosts) {
		return Err(err);
	}

	let pool_user_id = arg_matches.value_of("pool_user_id").unwrap().as_bytes().to_vec();
	let pool_user_auth = arg_matches.value_of("pool_user_auth").unwrap().as_bytes().to_vec();

	let pool_server_hosts: Vec<_>= arg_matches
		.values_of("pool_server")
		.unwrap()
		.map(String::from)
		.collect();
	if let Err(err) = check_socket_addresses(&pool_server_hosts) {
		return Err(err);
	}
	let mut pools = Vec::with_capacity(pool_server_hosts.len());
	for pool in &pool_server_hosts {
		pools.push(PoolInfo {
			host_port: pool.to_string(),
			user_id: pool_user_id.clone(),
			user_auth: pool_user_auth.clone(),
		});
	}

	let stratum_listen_bind = match arg_matches.value_of("stratum_listen_bind") {
		Some(v) => match v.to_string().parse() {
			Ok(sock_address) => Some(sock_address),
			Err(_) => {
				return Err("Failed to parse stratum_listen_bind into a socket address".to_string());
			}
		},
		None => None
	};
	let mining_listen_bind = match arg_matches.value_of("mining_listen_bind") {
		Some(v) => match v.to_string().parse() {
			Ok(sock_address) => Some(sock_address),
			Err(_) => {
				return Err("Failed to parse mining_listen_bind into a socket address".to_string());
			}
		},
		None => None
	};

	if stratum_listen_bind.is_none() && mining_listen_bind.is_none() {
		return Err("Need some listen bind".to_string());
	}

	let mining_auth_key = match arg_matches.value_of("mining_auth_key") {
		Some(v) => {
			match privkey::Privkey::from_str(&v.to_string()) {
				Ok(private_key) => {
					if !private_key.compressed {
						return Err("Private key must represent a compressed key".to_string());
					}
					Some(private_key.key)
				},
				Err(_) => {
					return Err("Failed to parse mining_auth_key into a private key".to_string());
				}
			}
		},
		None => None
	};

	if mining_listen_bind.is_some() && mining_auth_key.is_none() {
		return Err("Need some mining_auth_key for mining_listen_bind".to_string());
	}

	let payout_address_str = arg_matches.value_of("payout_address").unwrap();
	let payout_address = match Address::from_str(payout_address_str) {
		Ok(address) => address,
		Err(_) => {
			return Err("Failed to parse payout_address into a Bitcoin address".to_string());
		}
	};

	Ok(CommandLineArgs {
		job_provider_hosts,
		pools,
		stratum_listen_bind,
		mining_listen_bind,
		mining_auth_key,
		payout_address
	})
}

fn check_socket_addresses(addresses: &Vec<String>) -> Result<(), String> {
	for address in addresses {
		if address.to_socket_addrs().is_err() {
			return Err(format!("Bad socket address resolution: {}", address));
		}
	}
	Ok(())
}

fn main() {
	let args = match parse_command_line_arguments() {
		Ok(args) => args,
		Err(err) => {
			println!("Error parsing command line arguments: {}", err);
			return;
		}
	};

	let mut rt = tokio::runtime::Runtime::new().unwrap();
	rt.spawn(future::lazy(move || -> Result<(), ()> {
		let job_rx = WorkGetter::create(args.job_provider_hosts, args.pools, args.payout_address.clone().script_pubkey());

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

		if args.stratum_listen_bind.is_some() && args.mining_listen_bind.is_none() {
			bind_and_handle!(args.stratum_listen_bind, StratumServer::new(job_rx, None), StratumServer);
		} else if args.stratum_listen_bind.is_none() && args.mining_listen_bind.is_some() {
			bind_and_handle!(args.mining_listen_bind, MiningServer::new(job_rx, args.mining_auth_key.unwrap()), MiningServer);
		} else {
			let (mut stratum_tx, stratum_rx) = mpsc::unbounded();
			let (mut mining_tx, mining_rx) = mpsc::unbounded();
			tokio::spawn(job_rx.for_each(move |job| {
				mining_tx.start_send(job.clone()).unwrap();
				stratum_tx.start_send(job).unwrap();
				Ok(())
			}).then(|_| {
				Ok(())
			}));
			bind_and_handle!(args.stratum_listen_bind, StratumServer::new(stratum_rx, None), StratumServer);
			bind_and_handle!(args.mining_listen_bind, MiningServer::new(mining_rx, args.mining_auth_key.unwrap()), MiningServer);
		}

		Ok(())
	}));
	rt.shutdown_on_idle().wait().unwrap();
}
