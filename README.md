## XDP IP Counter
An eBPF XDP program that helps with finding IP addresses that have tried to reach out to a specific port during a certain interval (IPv4 and IPv6 with TCP or UDP payloads only). It serves the metrics in prometheus format as well as a list of IP addresses with some extra metadata.

The initial idea was to find out who is connected to what, specifically for services that does not provide such capabilities out of the box.

This project is a work in progress.

#### Technical Notes
- The return code for all received packets is always `XDP_PASS` and the default XDP attach mode is `SKB_MODE`.

- XDP programs are invoked right after the network driver recieves a packet. Since it doesn't know whether there is an open socket for a specific port or not, it's a good idea to specify ports you care about using `--ports` flag.

- Built with [Aya](https://github.com/aya-rs/aya) and Rust.

#### CLI --help Output
```
An eBPF XDP program that helps with finding IP addresses that have tried to reach out to a specific port during a certain interval. Metrics are served in prometheus format on :[server_port]/metrics and IPs are available on :[server_port]/list

Usage: xdp-ip-counter [OPTIONS]

Options:
  -i, --iface <IFACE>              Network Interface to attach eBPF program to [default: eth0]
  -p, --ports <PORTS>              Comma-separated ports to collect data for. 0 means all ports [default: 0]
  -w, --window <WINDOW>            Sampling interval in seconds. value must be divisable by 10 [default: 60]
  -s, --server-port <SERVER_PORT>  Port to serve prometheus metrics on (i.e. HTTP Server Port) [default: 3031]
      --serve-ip-list              Whether to serve a list of connected IP addresses on :[server_port]/list
  -h, --help                       Print help
```

#### Served Metrics/Data
##### Prometheus Metrics
```plain
# HELP active_users Number of users actively hitting on a specific port.
# TYPE active_users counter
active_users{network="IPv4",transport="TCP",port="22"} 8
# EOF
```
Available at `:[server_port]/metrics`, This indicates that 8 unique IPv4 addresses have tried to connect to port 22 over the past sampling interval.

##### IPs List
```plain
[
  {
    "ip": "xxx.xxx.xxx.xxx",
    "network": "IPv4",
    "transport": "TCP",
    "port": 22
  },
  {
    "ip": "yyy.yyy.yyy.yyy",
    "network": "IPv4",
    "transport": "TCP",
    "port": 22
  },
  ...
}
```

Served at `:[server_port]/list`

## Build and Run 

#### Static binary
1. Install rust stable toolchain: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
1. Install rust nightly toolchain with the rust-src component: `rustup toolchain install nightly --component rust-src`
1. Add x86_64-unknown-linux-musl target: `rustup target add x86_64-unknown-linux-musl`
1. Install bpf-linker: `cargo install bpf-linker`
1. Build eBPF: `cargo xtask build-ebpf --release`
1. Build binary: `cargo build --release --target=x86_64-unknown-linux-musl`
1. Run: `sudo ./target/x86_64-unknown-linux-musl/release/xdp-ip-counter --iface=eth0 --ports=80,22 --window=60 --server-port=3031 --serve-ip-list`

#### Debug Run
Run steps 1-4 and then: `RUST_LOG=info cargo xtask run -- --iface=eth0 --ports=80,22 --window=60 --server-port=3031 --serve-ip-list`

## To Do
- [x] IPv6 Support
- [ ] Show/Hide Local IP addresses via CLI flags 
- [ ] Use Prometheus Client Library instead of a custom one
- [ ] Add Support for more [IP Protocols](https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers)
- [ ] Cache counts for the duration of sampling interval
