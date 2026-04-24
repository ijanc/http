http - minimal HTTP/1.0 and HTTP/1.1 library
=============================================
http is a minimal, single-file HTTP library written in Rust, conforming
to RFC 1945 (HTTP/1.0) and RFC 2616 (HTTP/1.1).  It is meant to be
dropped into another project's source tree, or linked as a plain rlib.


Requirements
------------
In order to build http you need rustc (edition 2024).


Installation
------------
There are two ways to use http in another Rust project.

Drop-in source.  Copy http.rs into your project and declare it as a
module:

    mod http;

Linked rlib.  Build the library with make(1) and pass it to rustc:

    $ make
    $ rustc --extern http=build/libhttp.rlib -L build main.rs


Standards
---------
- RFC 1945 (HTTP/1.0)
- RFC 2616 (HTTP/1.1)


Download
--------
    got clone ssh://anon@ijanc.org/http
    git clone https://git.ijanc.org/http.git


License
-------
ISC - see LICENSE.
