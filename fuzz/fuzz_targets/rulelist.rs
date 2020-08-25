#![no_main]
use abnf::rulelist;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(data) = std::str::from_utf8(data) {
        if let Ok(parsed) = rulelist(data) {
            println!("{:?}", parsed);
        }
    }
});
