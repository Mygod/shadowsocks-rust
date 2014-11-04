#![feature(phase)]
#![feature(globs)]

extern crate getopts;
#[phase(plugin, link)]
extern crate log;

extern crate shadowsocks;

use getopts::{optopt, optflag, getopts, usage, Matches};

use std::os;

use std::io::net::udp::UdpSocket;
use std::io::net::tcp::TcpStream;
use std::io::net::ip::SocketAddr;
use std::io::net::ip::{IpAddr, Port};
use std::io::net::addrinfo::get_host_addresses;
use std::io::{MemWriter, BufReader};
use std::io::stdio::{stdin, stdout};
use std::io::{Reader, Writer, mod};

use shadowsocks::relay::socks5::*;

fn do_tcp(_: &Matches, svr_addr: &Address, proxy_addr: &SocketAddr) {
    let mut proxy_stream = TcpStream::connect(proxy_addr.ip.to_string().as_slice(), proxy_addr.port).unwrap();

    let shake_req = HandshakeRequest::new(vec![0x00]);
    shake_req.write_to(&mut proxy_stream).unwrap();
    let shake_resp = HandshakeResponse::read_from(&mut proxy_stream).unwrap();

    if shake_resp.chosen_method != 0x00 {
        panic!("Proxy server needs authentication");
    }

    let data = stdin().read_to_end().unwrap();

    let req_header = TcpRequestHeader::new(TcpConnect, svr_addr.clone());
    req_header.write_to(&mut proxy_stream).unwrap();
    proxy_stream.write(data.as_slice()).unwrap();

    let resp_header = TcpResponseHeader::read_from(&mut proxy_stream).unwrap();
    match resp_header.reply {
        Succeeded => {},
        _ => {
            panic!("Failed with error {}", resp_header.reply);
        }
    }

    io::util::copy(&mut proxy_stream, &mut stdout()).unwrap();
}

fn do_udp(matches: &Matches, svr_addr: &Address, proxy_addr: &SocketAddr) {
    let udp_proxy_addr = {
        let mut proxy_stream = TcpStream::connect(proxy_addr.ip.to_string().as_slice(), proxy_addr.port).unwrap();

        let shake_req = HandshakeRequest::new(vec![0x00]);
        shake_req.write_to(&mut proxy_stream).unwrap();
        let shake_resp = HandshakeResponse::read_from(&mut proxy_stream).unwrap();

        if shake_resp.chosen_method != 0x00 {
            panic!("Proxy server needs authentication");
        }

        let req_header = TcpRequestHeader::new(UdpAssociate, svr_addr.clone());
        req_header.write_to(&mut proxy_stream).unwrap();

        let resp_header = TcpResponseHeader::read_from(&mut proxy_stream).unwrap();
        match resp_header.reply {
            Succeeded => {},
            _ => {
                panic!("Failed with error {}", resp_header.reply);
            }
        }

        resp_header.address
    };

    let local_addr = SocketAddr {
        ip: from_str(matches.opt_str("b").expect("Require local address").as_slice()).unwrap(),
        port: from_str(matches.opt_str("l").expect("Require local port").as_slice()).unwrap(),
    };

    let mut udp_socket = UdpSocket::bind(local_addr).unwrap();

    let proxy_real_addr = match udp_proxy_addr {
        SocketAddress(sa) => sa,
        DomainNameAddress(dm) => {
            SocketAddr {
                ip: get_host_addresses(dm.domain_name.as_slice()).unwrap().head().unwrap().clone(),
                port: dm.port,
            }
        }
    };

    let data = stdin().read_to_end().unwrap();

    let mut bufw = MemWriter::new();
    let udp_header = UdpAssociateHeader::new(0, svr_addr.clone());
    udp_header.write_to(&mut bufw).unwrap();
    bufw.write(data.as_slice()).unwrap();
    udp_socket.send_to(bufw.unwrap().as_slice(), proxy_real_addr).unwrap();

    let mut buf = [0, ..0xffff];
    let (len, _) = udp_socket.recv_from(buf).unwrap();

    let mut bufr = BufReader::new(buf.slice_to(len));
    let _ = UdpAssociateHeader::read_from(&mut bufr).unwrap();

    io::util::copy(&mut bufr, &mut stdout()).unwrap();
}

fn main() {

    let opts = [
        optflag("h", "help", "Print help message"),
        optopt("s", "server-addr", "Server address", ""),
        optopt("p", "server-port", "Server port", ""),
        optopt("b", "local-addr", "Local address for binding", ""),
        optopt("l", "local-port", "Local port for binding", ""),
        optopt("x", "proxy-addr", "Proxy address", ""),
        optopt("o", "proxy-port", "Proxy port", ""),
        optopt("t", "protocol", "Protocol to use", "tcp"),
    ];

    let matches = getopts(os::args().tail(), opts).unwrap();

    if matches.opt_present("h") {
        println!("{}", usage(format!("Usage: {} [Options]", os::args()[0]).as_slice(),
                            opts));
        return;
    }

    let is_tcp = match matches.opt_str("t").expect("Required to specify protocol").as_slice() {
        "tcp" => true,
        "udp" => false,
        _ => panic!("Unsupported protocol")
    };

    let proxy_addr = SocketAddr {
        ip: from_str(matches.opt_str("x").expect("Require proxy address").as_slice()).unwrap(),
        port: from_str(matches.opt_str("o").expect("Require proxy port").as_slice()).unwrap(),
    };

    let svr_port: Port = from_str(matches.opt_str("p").expect("Require server port").as_slice()).unwrap();
    let svr_addr = match from_str::<IpAddr>(matches.opt_str("s").expect("Require server address").as_slice()) {
        Some(ip) => SocketAddress(SocketAddr {ip: ip, port: svr_port}),
        None => DomainNameAddress(DomainNameAddr {
                                                domain_name: matches.opt_str("s").unwrap(),
                                                port: svr_port}),
    };

    if is_tcp {
        do_tcp(&matches, &svr_addr, &proxy_addr);
    } else {
        do_udp(&matches, &svr_addr, &proxy_addr);
    }
}