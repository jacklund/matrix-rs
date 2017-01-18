#![feature(plugin)]
#![plugin(rocket_codegen)]

#![feature(proc_macro)]
#![feature(drop_types_in_const)]

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
extern crate toml;

mod client_api;
mod db;

use std::fs::File;
use std::io::Read;
use toml::Parser;

// This function panics if anything's wrong
fn read_config() -> toml::Table {
    // Read config file
    let mut file = File::open("matrix_rs.toml").unwrap();
    let mut config_string = String::new();
    file.read_to_string(&mut config_string).unwrap();
    let mut parser = Parser::new(&config_string);
    parser.parse().unwrap()
}

fn get_db(config: toml::Table) -> Box<db::DB> {
    match config.get("db") {
        Some(db_config) => return db::new(db_config),
        None => panic!("No DB config found!"),
    }
}

fn main() {
    let config = read_config();
    let db: Box<db::DB> = get_db(config);
    client_api::set_db(db);

    // Mount all the client API routes
    client_api::mount().launch();
}