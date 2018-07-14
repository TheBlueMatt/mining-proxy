// Plug in your business logic into these functions:

pub struct GenericAuthenticatorSettings { }
pub struct GenericAuthenticatorState { }

pub fn init_authenticator_settings() -> GenericAuthenticatorSettings {
	GenericAuthenticatorSettings { }
}

pub fn print_authenticator_parameters() { }

/// Returns true if the given parameter could be parsed into a setting this Authenticator understands
pub fn parse_authenticator_parameter(_settings: &mut GenericAuthenticatorSettings, _arg: &str) -> bool {
	// we have no settings for a Authenticator that just prints...
	false
}

pub fn setup_authenticator(_settings: GenericAuthenticatorSettings) -> GenericAuthenticatorState {
	GenericAuthenticatorState { }
}

/// Returns true if the given user_id/auth pair is valid for this pool. Note that the pool_proxy
/// stuff doesn't really bother with auth, so if you use it you probably can't reliably check
/// user_auth, but there probably isnt any reason to ever anyway...
pub fn check_user_auth(_state: &GenericAuthenticatorState, user_id: &Vec<u8>, user_auth: &Vec<u8>) -> bool {
	println!("User {} authed with pass {}", String::from_utf8_lossy(user_id), String::from_utf8_lossy(user_auth));
	true
}