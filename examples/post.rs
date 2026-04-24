// vim: set tw=79 cc=80 ts=4 sw=4 sts=4 et :
//
// Copyright (c) 2026 Murilo Ijanc' <murilo@ijanc.org>
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
//

//! POST a body to a URL and print the response.
//!
//! Usage: ex-post <url> <body|->
//!
//! If the body argument is `-`, the body is read from stdin.

use std::env;
use std::io::{self, Read};
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: ex-post <url> <body|->");
        process::exit(1);
    }
    let url = &args[1];
    let body = if args[2] == "-" {
        let mut s = String::new();
        if let Err(e) = io::stdin().read_to_string(&mut s) {
            eprintln!("ex-post: read stdin: {e}");
            process::exit(1);
        }
        s
    } else {
        args[2].clone()
    };

    let resp = match http::post(url)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("ex-post: {e}");
            process::exit(2);
        }
    };
    println!("{} {} {}", resp.version, resp.status, resp.reason);
    for (name, value) in resp.headers.iter() {
        println!("{name}: {value}");
    }
    println!();
    match resp.body_string() {
        Ok(s) => print!("{s}"),
        Err(e) => {
            eprintln!("ex-post: read body: {e}");
            process::exit(2);
        }
    }
}
