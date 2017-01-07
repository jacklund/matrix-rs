#![feature(plugin)]
#![plugin(rocket_codegen)]

#![feature(proc_macro)]

extern crate regex;
extern crate rocket;
#[macro_use]
extern crate rocket_contrib;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;

mod client_api;

fn main() {
    client_api::mount().launch();
}