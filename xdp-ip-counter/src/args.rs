use clap::{ArgAction, Parser};

/// An eBPF XDP program that helps with finding IP addresses that have tried to reach out to a specific port during a certain interval.
/// Metrics are served in prometheus format on :[server_port]/metrics and
/// IPs are available on :[server_port]/list
#[derive(Debug, Parser)]
#[command(version)]
pub struct Args {
    #[clap(short, long, default_value = "eth0")]
    /// Network Interface to attach eBPF program to.
    pub iface: String,

    #[clap(short, long, default_value = "0")]
    /// Comma-separated ports to collect data for. 0 means all ports.
    pub ports: String,

    #[clap(short, long, default_value = "60")]
    /// Sampling interval in seconds. value must be divisable by 10.
    pub window: String,

    #[clap(short, long, default_value = "3031")]
    /// Port to serve prometheus metrics on (i.e. HTTP Server Port)
    pub server_port: String,

    #[clap(long, action=ArgAction::SetTrue)]
    /// Whether to serve a list of connected IP addresses on :[server_port]/list
    pub serve_ip_list: bool,
}

impl Args {
    pub fn parse_custom_ports(&self) -> Option<Vec<u16>> {
        let ports: Vec<u16> = self
            .ports
            .trim()
            .split(',')
            .map(|ports| match ports.parse::<u16>() {
                Ok(port) => port,
                Err(err) => {
                    panic!(
                        "ports must be positive comma seperated number from 0 to 65536: {}",
                        err
                    )
                }
            })
            .collect();

        if ports.len() == 1 && ports.first().unwrap() == &0 {
            None
        } else {
            Some(ports)
        }
    }

    pub fn parse_window(&self) -> u64 {
        let window = self
            .window
            .trim()
            .parse::<u64>()
            .expect("windows must be a positive integer and divisable by 10");

        if window % 10 != 0 {
            panic!("windows must be a positive integer and divisable by 10");
        }

        window
    }

    pub fn parse_server_port(&self) -> u16 {
        let port = self
            .server_port
            .trim()
            .parse::<u16>()
            .expect("port must be a positive integer");

        port
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_parse_custom_ports() {
        let args = Args {
            iface: "eth0".to_string(),
            ports: "80,8341,22".to_string(),
            window: "60".to_string(),
            server_port: "3031".to_owned(),
            serve_ip_list: false,
        };

        let expected = vec![80, 8341, 22];
        match args.parse_custom_ports() {
            Some(ports) => {
                assert_eq!(ports, expected)
            }
            None => {
                assert!(false)
            }
        }
    }

    #[test]
    fn test_parse_window() {
        let args = Args {
            iface: "eth0".to_string(),
            ports: "80,8341,22".to_string(),
            window: "60".to_string(),
            server_port: "3031".to_owned(),
            serve_ip_list: false,
        };

        let expected = 60;
        assert_eq!(args.parse_window(), expected)
    }

    #[test]
    fn test_parse_server_port() {
        let args = Args {
            iface: "eth0".to_string(),
            ports: "80,8341,22".to_string(),
            window: "60".to_string(),
            server_port: "3031".to_owned(),
            serve_ip_list: false,
        };

        let expected = 3031;
        assert_eq!(args.parse_server_port(), expected)
    }
}
