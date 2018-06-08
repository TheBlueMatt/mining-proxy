// This module is useful for anything that needs to speak pool+work protocols to get remote work
// (eg for a mining client, or a proxy). Simpler clients may wish to only speak work protocol.

use connection_maintainer::*;
use msg_framing::*;
use pool_client::*;
use work_client::*;
use client_utils::*;

use futures::sync::mpsc;

use bitcoin::blockdata::script::Script;

use futures::future;
use futures::{Future,Stream,Sink};

use tokio;

use std::sync::{Arc, Mutex};

struct JobInfo {
	payout_script: Script,
	cur_job: Option<(BlockTemplate, Option<CoinbasePrefixPostfix>, Arc<EventualTxData>)>,
	cur_job_source: Option<Arc<JobProviderHandler>>,
	cur_pool: Option<(PoolPayoutInfo, Option<PoolDifficulty>)>,
	cur_pool_source: Option<Arc<PoolHandler>>,
	job_tx: mpsc::Sender<WorkInfo>,
}

pub struct PoolInfo {
	pub host_port: String,
	pub user_id: Vec<u8>,
	pub user_auth: Vec<u8>,
}

pub struct WorkGetter {
}

impl WorkGetter {
	pub fn create(job_provider_hosts: Vec<String>, mut pool_server: Vec<PoolInfo>, solo_payout_script: Script) -> mpsc::Receiver<WorkInfo> {
		let (job_tx, job_rx) = mpsc::channel(5);
		let cur_work_rc = Arc::new(Mutex::new(JobInfo {
			payout_script: solo_payout_script,
			cur_job: None,
			cur_job_source: None,
			cur_pool: None,
			cur_pool_source: None,
			job_tx: job_tx,
		}));

		tokio::spawn(future::lazy(move || -> Result<(), ()> {
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

			for (idx, pool) in pool_server.drain(..).enumerate() {
				let (mut handler, mut pool_rx) = PoolHandler::new(None, pool.user_id, pool.user_auth, idx);
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
				ConnectionMaintainer::new(pool.host_port, handler).make_connection();
			}

			Ok(())
		}));

		job_rx
	}
}
