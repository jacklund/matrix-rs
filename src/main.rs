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

enum Errors {
    IOError(std::io::Error),
    ParseError(Vec<toml::ParserError>),
}

impl From<std::io::Error> for Errors {
    fn from(error: std::io::Error) -> Self {
        Errors::IOError(error)
    }
}

impl From<Vec<toml::ParserError>> for Errors {
    fn from(errors: Vec<toml::ParserError>) -> Self {
        Errors::ParseError(errors)
    }
}

impl std::fmt::Debug for Errors {
    fn fmt(&self, format: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            &Errors::IOError(ref value) => value.fmt(format),
            &Errors::ParseError(ref value) => value.fmt(format),
        }
    }
}

// This function panics if anything's wrong
fn read_config() -> Result<toml::Table, Errors> {
    // Read config file
    let mut file = try!(File::open("matrix_rs.toml"));
    let mut config_string = String::new();
    try!(file.read_to_string(&mut config_string));
    let mut parser = Parser::new(&config_string);
    let config: Option<toml::Table> = parser.parse();
    match config {
        Some(config_value) => Ok(config_value),
        None => panic!("{:?}", parser.errors),
    }
}

fn initialize_db(config: toml::Table) {
    match config.get("db") {
        Some(db_config) => db::initialize(db_config),
        None => panic!("No DB config found!"),
    }
}

fn main() {
    match read_config() {
        Ok(config) => initialize_db(config),
        Err(error) => panic!("{:?}", error),
    }

    // Mount all the client API routes
    client_api::mount().launch();
}