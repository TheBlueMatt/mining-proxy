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

/// Merges some work and some pool payout information to build a job to mine on.
/// If both pool and our_payout_script are None we can't build a job.
/// If pool or work are invalid, None will sometimes be returned, but invalid work may also be
/// generated. Generally, pool and work are trusted to be well-formed and compatible.
pub fn merge_job_pool(our_payout_script: &Option<Script>, work: &WorkProviderJob, pool: Option<&PoolProviderJob>, user: Option<&PoolProviderUserJob>) -> Option<WorkInfo> {
	let mut template = work.template.clone();

	let mut outputs = Vec::with_capacity(template.appended_coinbase_outputs.len() + 1);
	for output in template.appended_coinbase_outputs.iter() {
		if output.value != 0 { panic!("We should have checked this on the recv end!"); }
	}

	match &work.coinbase_prefix_postfix {
		&Some(ref postfix) => {
			template.coinbase_prefix.extend_from_slice(&postfix.coinbase_prefix_postfix[..]);
		},
		&None => {}
	}

	if template.coinbase_value_remaining <= 0 {
		println!("Work provider returning 0-value work! Can't mine!");
		return None;
	}

	let work_target = template.target.clone();

	match pool {
		Some(&PoolProviderJob { ref payout_info, .. }) => {
			template.coinbase_prefix.extend_from_slice(&payout_info.pool_info[..]);

			let mut constant_value_output = 0;
			for output in payout_info.appended_outputs.iter() {
				if output.value > 21000000*100000000 || output.value + constant_value_output > 21000000*100000000 {
					println!("Pool trying to claim > 21 million BTC in value! Can't mine!");
					return None;
				}
				constant_value_output += output.value;
			}

			let value_remaining = (template.coinbase_value_remaining as i64) - (constant_value_output as i64);
			if value_remaining <= 0 {
				println!("Pool requiring {} in output value, work provider only finding {}! Can't mine!", constant_value_output, template.coinbase_value_remaining);
				return None;
			}

			outputs.push(TxOut {
				value: value_remaining as u64,
				script_pubkey: payout_info.remaining_payout.clone(),
			});

			outputs.extend_from_slice(&payout_info.appended_outputs[..]);

			match user {
				Some(&PoolProviderUserJob { ref coinbase_postfix, ref target }) => {
					template.target = utils::max_le(template.target, *target);

					if !template.coinbase_postfix.is_empty() { panic!("We should have checked this on the recv end!"); }
					template.coinbase_postfix.extend_from_slice(coinbase_postfix);
				},
				None => {}
			}
		},
		None => {
			if let &Some(ref script) = our_payout_script {
				println!("No available pool info! Solo mining!");
				outputs.push(TxOut {
					value: template.coinbase_value_remaining,
					script_pubkey: script.clone(),
				});
			} else {
				return None;
			}
		}
	}

	outputs.extend_from_slice(&template.appended_coinbase_outputs[..]);

	template.appended_coinbase_outputs = outputs;

	let template_rc = Arc::new(template);

	let (solution_tx, solution_rx) = mpsc::unbounded();
	let tx_data_ref = work.tx_data.clone();
	let template_ref = template_rc.clone();
	let work_provider = work.provider.clone();
	let pool_provider = if let Some(ref pool_info) = pool {
		Some(pool_info.provider.clone()) } else { None };

	tokio::spawn(solution_rx.for_each(move |nonces: Arc<(WinningNonce, Sha256dHash)>| {
		if utils::does_hash_meet_target(&nonces.1[..], &work_target[..]) {
			work_provider.send_nonce(nonces.0.clone());
		}
		match pool_provider {
			Some(ref provider) => {
				let provider_ref = provider.clone();
				let template_ref_2 = template_ref.clone();
				tx_data_ref.get_and(move |txn, prev_header, extra_block_data| {
					let source_clone = provider_ref.clone();
					source_clone.send_nonce(&nonces, &template_ref_2, &txn, &prev_header, &extra_block_data);
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
}
