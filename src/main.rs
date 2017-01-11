#![feature(plugin)]
#![plugin(rocket_codegen)]

#![feature(proc_macro)]

#[macro_use]
extern crate lazy_static;
extern crate regex;
extern crate rocket;
#[macro_use]
extern crate rocket_contrib;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate serde_test;

mod client_api;

fn main() {
    client_api::mount().launch();
}