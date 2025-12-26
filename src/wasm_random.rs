use getrandom::register_custom_getrandom;

fn custom_getrandom(_buf: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}

register_custom_getrandom!(custom_getrandom);