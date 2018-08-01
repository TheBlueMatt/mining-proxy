// With this mod, shares and weak blocks will be sent to kafka message queue,
// with information in json format with attributes of type `ShareMessage`.

use bitcoin::blockdata::block::BlockHeader;

use rdkafka::config::ClientConfig;
use rdkafka::producer::{FutureProducer, FutureRecord};

use futures::Future;

use serde_json;

use tokio;

use utils;

// Kafka topics for shares and weak_blocks;
const KAFKA_SHARES_TOPIC_POSTFIX: &'static str = "BetterHash-Shares-Topic";

pub struct KafkaSubmitterSettings {
	kafka_brokers: Option<String>,
	kafka_topic_prefix: Option<String>,
}
pub struct KafkaSubmitterState {
	topic: String,
	kafka_producer: FutureProducer,
}

pub fn init_submitter_settings() -> KafkaSubmitterSettings {
	KafkaSubmitterSettings {
		kafka_brokers: None,
		kafka_topic_prefix: None,
	}
}

pub fn print_submitter_parameters() {
	println!("--kafka_brokers - kafka brokers");
	println!("--kafka_topic_prefix - kafka topic prefix for shares(Optional)");
}

/// Returns true if the given parameter could be parsed into a setting this submitter understands
pub fn parse_submitter_parameter(settings: &mut KafkaSubmitterSettings, arg: &str) -> bool {
	if arg.starts_with("--kafka_brokers") {
		if settings.kafka_brokers.is_some() {
			println!("Cannot specify multiple kafka_brokers, specify brokers togather instead");
			false
		} else {
			settings.kafka_brokers = Some(arg.split_at(16).1.to_string());
			true
		}
	} else if arg.starts_with("--kafka_topic_prefix") {
		if settings.kafka_topic_prefix.is_some() {
			println!("Cannot specify multiple kafka_topic_prefix");
			false
		} else {
			settings.kafka_topic_prefix = Some(arg.split_at(21).1.to_string());
			true
		}
	} else {
		false
	}
}

pub fn setup_submitter(settings: KafkaSubmitterSettings) -> KafkaSubmitterState {
	let topic = if let Some(prefix) = settings.kafka_topic_prefix {
		prefix + KAFKA_SHARES_TOPIC_POSTFIX
	} else {
		KAFKA_SHARES_TOPIC_POSTFIX.to_string()
	};

	if settings.kafka_brokers.is_none() {
		println!("Need some kafka brokers, build with a generic submitter if you want to just get prints");
		panic!();
	}

	// Setup optional kafka producer to send shares
	let kafka_producer = ClientConfig::new()
		.set("bootstrap.servers", &settings.kafka_brokers.unwrap())
		.set("produce.offset.report", "true")
		.set("message.timeout.ms", "5000")
		.create()
		.expect("Kafka Producer creation error");

	KafkaSubmitterState {
		topic,
		kafka_producer,
	}
}

// Serialize pool share
#[derive(Serialize)]
struct ShareMessage {
	user: String,       // miner username
	worker: String,     // miner workername
	payout: u64,        // claimed value of the share - payout will be min(median share value, this value)
	client_target: u8,  // client target
	leading_zeros: u8,  // share target
	version: u32,       // version
	nbits: u32,         // nbits
	time: u32,          // share tsp
	hash: String,       // share hash
	is_good_block: bool,// potential good block tag
	is_weak_block: bool,// weak block tag
}

pub fn share_submitted(state: &KafkaSubmitterState, user_id: &Vec<u8>, user_tag_1: &Vec<u8>, value: u64, header: &BlockHeader, leading_zeros: u8, required_leading_zeros: u8) {
	println!("Got valid share with value {} from \"{}\" from machine identified as \"{}\"", value, String::from_utf8_lossy(user_id), String::from_utf8_lossy(user_tag_1));

	tokio::spawn(state.kafka_producer.send(
		FutureRecord::to(&state.topic)
			.key("")
			.payload(&serde_json::to_string(&ShareMessage {
				user: String::from_utf8_lossy(&user_id).to_string(),
				worker: String::from_utf8_lossy(&user_tag_1).to_string(),
				payout: value,
				client_target: required_leading_zeros,
				leading_zeros,
				version: header.version,
				nbits: header.bits,
				time: header.time,
				hash: String::new(),  // We only include hash for weak block
				is_good_block: false,
				is_weak_block: false,
			}).unwrap()),
	0).then(|result| {
		match result {
			Ok(Ok(_)) => {},
			Ok(Err((e, _))) => println!("Error: {:?}", e),
			Err(_) => println!("Produce future cancelled"),
		}
		Ok(())
	}));
}

pub fn weak_block_submitted(state: &KafkaSubmitterState, user_id: &Vec<u8>, user_tag_1: &Vec<u8>, value: u64, header: &BlockHeader, txn: &Vec<Vec<u8>>, _extra_block_data: &Vec<u8>,
	leading_zeros: u8, required_leading_zeros: u8, block_hash: &[u8]) {
	println!("Got valid weak block with value {} from \"{}\" with {} txn from machine identified as \"{}\"", value, String::from_utf8_lossy(user_id), txn.len(), String::from_utf8_lossy(user_tag_1));
	
	let (block_target, negative, overflow) = utils::nbits_to_target(header.bits);
	let mut is_good_block = false;
	if negative || overflow {
		//TODO: Not sure how to handle this case yet
		println!("We got block target negative or overflow!");
	} else {
		is_good_block = utils::does_hash_meet_target(&block_hash[..], &block_target[..]);
	}
	tokio::spawn(state.kafka_producer.send(
		FutureRecord::to(&state.topic)
			.key("")
			.payload(&serde_json::to_string(&ShareMessage {
				user: String::from_utf8_lossy(&user_id).to_string(),
				worker: String::from_utf8_lossy(&user_tag_1).to_string(),
				payout: value,
				client_target: required_leading_zeros,
				leading_zeros,
				version: header.version,
				nbits: header.bits,
				time: header.time,
				hash: utils::bytes_to_hex(block_hash),
				is_good_block,
				is_weak_block: true,
			}).unwrap()),
	0).then(|result| {
		match result {
			Ok(Ok(_)) => {},
			Ok(Err((e, _))) => println!("Error: {:?}", e),
			Err(_) => println!("Produce future cancelled"),
		}
		Ok(())
	}));
}
