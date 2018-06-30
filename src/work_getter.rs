// This module is useful for anything that needs to speak pool+work protocols to get remote work
// (eg for a mining client, or a proxy). Simpler clients may wish to only speak work protocol.

use connection_maintainer::*;
use pool_client::*;
use work_client::*;
use work_info::*;

use msg_framing::PoolUserAuth;

use futures::sync::mpsc;

use bitcoin::blockdata::script::Script;

use futures::future;
use futures::{Future,Stream,Sink};

use tokio;

use std;
use std::cmp;
use std::sync::{Arc, Mutex};

struct PoolProviderHolder {
	is_connected: bool,
	last_job: Option<PoolProviderJob>,
	last_user_job: Option<PoolProviderUserJob>,
}

pub struct MultiPoolProvider {
	cur_pool: usize,
	pools: Vec<PoolProviderHolder>,
	job_tx: mpsc::UnboundedSender<PoolProviderUserWork>,
}

pub struct PoolInfo {
	pub host_port: String,
	pub user_id: Vec<u8>,
	pub user_auth: Vec<u8>,
}

pub struct PoolProviderUserWork {
	pub payout_info: PoolProviderJob,
	pub user_payout_info: PoolProviderUserJob,
}

impl MultiPoolProvider {
	pub fn create(mut pool_hosts: Vec<PoolInfo>) -> mpsc::UnboundedReceiver<PoolProviderUserWork> {
		let (job_tx, job_rx) = mpsc::unbounded();
		let cur_work_rc = Arc::new(Mutex::new(MultiPoolProvider {
			cur_pool: std::usize::MAX,
			pools: Vec::with_capacity(pool_hosts.len()),
			job_tx: job_tx,
		}));

		tokio::spawn(future::lazy(move || -> Result<(), ()> {
			for (idx, pool) in pool_hosts.drain(..).enumerate() {
				let (mut auth_write, auth_read) = mpsc::channel(5);
				let (mut handler, mut pool_rx) = PoolHandler::new(None, auth_read);
				auth_write.start_send(PoolAuthAction::AuthUser(PoolUserAuth {
					suggested_target: [0xff; 32],
					minimum_target: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0], // Diff 1
					user_id: pool.user_id,
					user_auth: pool.user_auth,
				})).unwrap();
				cur_work_rc.lock().unwrap().pools.push(PoolProviderHolder {
					is_connected: false,
					last_job: None,
					last_user_job: None,
				});

				let work_rc = cur_work_rc.clone();
				tokio::spawn(pool_rx.for_each(move |job| {
					let mut cur_work = work_rc.lock().unwrap();
					macro_rules! provider_disconnect {
						() => {
							if cur_work.pools[idx].is_connected {
								cur_work.pools[idx].is_connected = false;
								if cur_work.cur_pool == idx {
									// Prefer pools which are connected, then follow the order they
									// were provided in...
									let mut lowest_with_work = std::usize::MAX;
									for (iter_idx, pool) in cur_work.pools.iter().enumerate() {
										if pool.last_job.is_some() && pool.last_user_job.is_some() {
											if pool.is_connected {
												lowest_with_work = iter_idx;
												break;
											} else {
												lowest_with_work = cmp::min(lowest_with_work, iter_idx);
											}
										}
									}
									if lowest_with_work != std::usize::MAX {
										let msg = {
											let new_pool = &cur_work.pools[lowest_with_work];
											PoolProviderUserWork {
												payout_info: new_pool.last_job.as_ref().unwrap().clone(),
												user_payout_info: new_pool.last_user_job.as_ref().unwrap().clone(),
											}
										};
										cur_work.job_tx.start_send(msg).unwrap();
									}
								}
							}
						}
					}
					match job {
						PoolProviderAction::UserUpdate { update, .. } => {
							cur_work.pools[idx].is_connected = true;
							if cur_work.cur_pool >= idx && cur_work.pools[idx].last_job.is_some() {
								cur_work.cur_pool = idx;
								let payout_info = cur_work.pools[idx].last_job.as_ref().unwrap().clone();
								cur_work.job_tx.start_send(PoolProviderUserWork {
									payout_info,
									user_payout_info: update.clone(),
								}).unwrap();
							}
							cur_work.pools[idx].last_user_job = Some(update);
						},
						PoolProviderAction::PoolUpdate { info } => {
							cur_work.pools[idx].is_connected = true;
							if cur_work.cur_pool >= idx && cur_work.pools[idx].last_user_job.is_some() {
								cur_work.cur_pool = idx;
								let user_payout_info = cur_work.pools[idx].last_user_job.as_ref().unwrap().clone();
								cur_work.job_tx.start_send(PoolProviderUserWork {
									payout_info: info.clone(),
									user_payout_info,
								}).unwrap();
							}
							cur_work.pools[idx].last_job = Some(info);
						},
						PoolProviderAction::UserReject { .. } => provider_disconnect!(),
						PoolProviderAction::ProviderDisconnected => provider_disconnect!(),
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

pub struct WorkGetter {
	payout_script: Option<Script>,
	cur_work: Option<WorkProviderJob>,
	cur_pool: Option<PoolProviderUserWork>,
}

impl WorkGetter {
	pub fn create(job_provider_hosts: Vec<String>, pool_server: Vec<PoolInfo>, solo_payout_script: Script) -> mpsc::UnboundedReceiver<WorkInfo> {
		let (mut job_tx, job_rx) = mpsc::unbounded();
		let cur_work_rc = Arc::new(Mutex::new(WorkGetter {
			payout_script: Some(solo_payout_script),
			cur_work: None,
			cur_pool: None,
		}));

		let job_work_rc = cur_work_rc.clone();
		let mut job_work_tx = job_tx.clone();
		tokio::spawn(MultiJobProvider::create(job_provider_hosts).for_each(move |work_update| {
			let mut cur_work = job_work_rc.lock().unwrap();
			cur_work.cur_work = Some(work_update);
			let cur_pool = if let &Some(ref pool) = &cur_work.cur_pool { Some(&pool.payout_info) } else { None };
			let cur_user = if let &Some(ref user) = &cur_work.cur_pool { Some(&user.user_payout_info) } else { None };
			if let Some(work) = merge_job_pool(&cur_work.payout_script, cur_work.cur_work.as_ref().unwrap(), cur_pool, cur_user) {
				job_work_tx.start_send(work).unwrap();
			}
			Ok(())
		}));
		tokio::spawn(MultiPoolProvider::create(pool_server).for_each(move |pool_update| {
			let mut cur_work = cur_work_rc.lock().unwrap();
			if let Some(ref work) = cur_work.cur_work {
				if let Some(work) = merge_job_pool(&cur_work.payout_script, work, Some(&pool_update.payout_info), Some(&pool_update.user_payout_info)) {
					job_tx.start_send(work).unwrap();
				}
			}
			cur_work.cur_pool = Some(pool_update);
			Ok(())
		}));

		job_rx
	}
}
