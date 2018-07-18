// We will need a simple redis command for authentication now.
// Set "BetterHash:AuthorizedUsers" should be created in redis database, and fill with 
// authorized users. We use `sismember` command to check if connected user is authorized.

extern crate simple_redis;

use std::sync::Mutex;
use std::str;

// Redis set which includes all valid miner usernames.
const REDIS_AUTHORIZED_USERS_KEY: &'static str = "BetterHash:AuthorizedUsers";

pub struct RedisAuthenticatorSettings {
	redis_url: Option<String>
}

pub struct RedisAuthenticatorState {
	client: Mutex<simple_redis::client::Client>,
	users_key: String,
}

pub fn init_authenticator_settings() -> RedisAuthenticatorSettings {
	RedisAuthenticatorSettings {
		redis_url: None,
	}
}

pub fn print_authenticator_parameters() {
	println!("--redis_url - Redis url: redis://host:port/");
}

/// Returns true if the given parameter could be parsed into a setting this Authenticator understands
pub fn parse_authenticator_parameter(settings: &mut RedisAuthenticatorSettings, arg: &str) -> bool {
	if arg.starts_with("--redis_url") {
		if settings.redis_url.is_some() {
			println!("Cannot specify multiple redis_urls");
			false
		} else {
			let redis_url = arg.split_at(12).1;
			if !redis_url.starts_with("redis://") {
				println!("Please provide a valid redis url: redis://host:ip/");
				panic!();
			}
			settings.redis_url = Some(redis_url.to_string());
			true
		}
	} else {
		false
	}
}

pub fn setup_authenticator(settings: RedisAuthenticatorSettings) -> RedisAuthenticatorState {
	if settings.redis_url.is_none() {
		println!("Need redis url, build with a generic Authenticator if you want to just get prints");
		panic!();
	}

	// Redis connection resiliency will be handled by simple-redis
	let client = match simple_redis::create(&settings.redis_url.unwrap()) {
		Ok(client) => client,
		Err(e) => {
			panic!("Failed to connect to redis: {:?}", e);
		},
	};

	RedisAuthenticatorState {
		client: Mutex::new(client),
		users_key: REDIS_AUTHORIZED_USERS_KEY.to_string(),
	}
}

/// Returns true if the given user_id/auth pair is valid for this pool. Note that the pool_proxy
/// stuff doesn't really bother with auth, so if you use it you probably can't reliably check
/// user_auth, but there probably isnt any reason to ever anyway...
pub fn check_user_auth(state: &RedisAuthenticatorState, user_id: &Vec<u8>, _user_auth: &Vec<u8>) -> bool {
	if let Ok(user_id_str) = str::from_utf8(user_id) {
		// Maybe convert to future for authentication process?
		let mut client = state.client.lock().unwrap();
		match client.sismember(&state.users_key, user_id_str) {
			Ok(authorized) => {
				println!("Authentication of user {} {}", user_id_str, if authorized { "succeeded" } else { "failed" });
				authorized
			},
			Err(e) => {
				println!("Failed to interact with redis: {:?}", e);
				false
			},
		}
	} else {
		println!("Encountered non-utf8 username bytes: {:?}", user_id);
		false
	}
}
