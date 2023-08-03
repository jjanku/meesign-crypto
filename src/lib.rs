// mod auth;
// pub mod c_api;
pub mod protocol;
pub mod wasm_api;

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/meesign.rs"));
}
