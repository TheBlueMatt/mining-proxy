use msg_framing::*;
use pool_client::*;
use work_client::*;
use utils;

use futures::sync::mpsc;

use bitcoin::blockdata::transaction::TxOut;
use bitcoin::blockdata::script::Script;
use bitcoin::util::hash::Sha256dHash;

use futures::future;
use futures::{Future,Stream};

use tokio;

use std::sync::Arc;

#[derive(Clone)]
pub struct WorkInfo {
	pub template: Arc<BlockTemplate>,
	pub solutions: mpsc::UnboundedSender<Arc<(WinningNonce, Sha256dHash)>>,
}

pub fn merge_job_pool(our_payout_script: Script, job_info: &Option<(BlockTemplate, Option<CoinbasePrefixPostfix>, Arc<EventualTxData>)>, job_source: Option<Arc<JobProviderHandler>>, payout_info: &Option<(PoolPayoutInfo, Option<PoolDifficulty>)>, payout_source: Option<Arc<PoolHandler>>) -> Option<WorkInfo> {
	match job_info {
		&Some((ref template_ref, ref coinbase_prefix_postfix, ref tx_data)) => {
			let mut template = template_ref.clone();

			let mut outputs = Vec::with_capacity(template.appended_coinbase_outputs.len() + 2);
			let mut constant_value_output = 0;
			for output in template.appended_coinbase_outputs.iter() {
				if output.value > 21000000*100000000 {
					return None;
				}
				constant_value_output += output.value;
			}

			match coinbase_prefix_postfix {
				&Some(ref postfix) => {
					template.coinbase_prefix.extend_from_slice(&postfix.coinbase_prefix_postfix[..]);
				},
				&None => {}
			}

			if template.coinbase_value_remaining <= 0 {
				return None;
			}

			let work_target = template.target.clone();

			match payout_info {
				&Some((ref info, ref difficulty)) => {
					for output in info.appended_outputs.iter() {
						if output.value > 21000000*100000000 {
							return None;
						}
						constant_value_output += output.value;
					}

					let value_remaining = (template.coinbase_value_remaining as i64) - (constant_value_output as i64);
					if value_remaining <= 0 {
						return None;
					}

					outputs.push(TxOut {
						value: value_remaining as u64,
						script_pubkey: info.remaining_payout.clone(),
					});

					outputs.extend_from_slice(&info.appended_outputs[..]);

					match difficulty {
						&Some(ref pool_diff) => {
							template.target = utils::max_le(template.target, pool_diff.share_target);
							template.target = utils::max_le(template.target, pool_diff.weak_block_target);
						},
						&None => {}
					}

					if !template.coinbase_postfix.is_empty() { panic!("We should have checked this on the recv end!"); }
					template.coinbase_postfix.extend_from_slice(&info.coinbase_postfix[..]);
				},
				&None => {
					outputs.push(TxOut {
						value: template.coinbase_value_remaining,
						script_pubkey: our_payout_script,
					});
				}
			}

			outputs.extend_from_slice(&template.appended_coinbase_outputs[..]);

			template.appended_coinbase_outputs = outputs;

			let template_rc = Arc::new(template);

			let (solution_tx, solution_rx) = mpsc::unbounded();
			let tx_data_ref = tx_data.clone();
			let template_ref = template_rc.clone();
			tokio::spawn(solution_rx.for_each(move |nonces: Arc<(WinningNonce, Sha256dHash)>| {
				match job_source {
					Some(ref source) => {
						if utils::does_hash_meet_target(&nonces.1[..], &work_target[..]) {
							source.send_nonce(nonces.0.clone());
						}
					},
					None => {}
				}
				match payout_source {
					Some(ref source) => {
						let source_ref = source.clone();
						let template_ref_2 = template_ref.clone();
						tx_data_ref.get_and(move |txn, prev_header| {
							let source_clone = source_ref.clone();
							source_clone.send_nonce(&nonces, &template_ref_2, &txn, &prev_header);
						});
					},
					None => {}
				}
				future::result(Ok(()))
			}).then(|_| {
				future::result(Ok(()))
			}));

			Some(WorkInfo {
				template: template_rc,
				solutions: solution_tx
			})
		},
		&None => None
	}
}

