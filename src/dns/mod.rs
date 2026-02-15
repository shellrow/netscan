use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::thread;
use std::time::Duration;

use futures::stream::{self, StreamExt};
use hickory_resolver::TokioResolver;

#[cfg(not(any(unix, target_os = "windows")))]
use hickory_resolver::config::ResolverConfig;
#[cfg(not(any(unix, target_os = "windows")))]
use hickory_resolver::name_server::TokioConnectionProvider;

#[cfg(not(target_os = "windows"))]
const DEFAULT_TIMEOUT: Duration = Duration::from_millis(200);
#[cfg(not(target_os = "windows"))]
const DEFAULT_TIMEOUT_GLOBAL: Duration = Duration::from_millis(1000);
#[cfg(target_os = "windows")]
const DEFAULT_TIMEOUT: Duration = Duration::from_millis(20);
#[cfg(target_os = "windows")]
const DEFAULT_TIMEOUT_GLOBAL: Duration = Duration::from_millis(1000);

#[cfg(any(unix, target_os = "windows"))]
fn get_resolver() -> Option<TokioResolver> {
    TokioResolver::builder_tokio()
        .ok()
        .map(|resolver| resolver.build())
}

#[cfg(not(any(unix, target_os = "windows")))]
fn get_resolver() -> Option<TokioResolver> {
    Some(
        TokioResolver::builder_with_config(
            ResolverConfig::default(),
            TokioConnectionProvider::default(),
        )
        .build(),
    )
}

pub fn lookup_host_name(host_name: &str) -> Option<IpAddr> {
    let ip_vec: Vec<IpAddr> = resolve_domain(host_name.to_string());
    let mut ipv6_vec: Vec<IpAddr> = vec![];
    for ip in ip_vec {
        match ip {
            IpAddr::V4(_) => {
                return Some(ip);
            }
            IpAddr::V6(_) => {
                ipv6_vec.push(ip);
            }
        }
    }
    if !ipv6_vec.is_empty() {
        Some(ipv6_vec[0])
    } else {
        None
    }
}

pub async fn lookup_host_name_async(host_name: String) -> Option<IpAddr> {
    let ip_vec: Vec<IpAddr> = resolve_domain_async(host_name).await;
    let mut ipv6_vec: Vec<IpAddr> = vec![];
    for ip in ip_vec {
        match ip {
            IpAddr::V4(_) => {
                return Some(ip);
            }
            IpAddr::V6(_) => {
                ipv6_vec.push(ip);
            }
        }
    }
    if !ipv6_vec.is_empty() {
        Some(ipv6_vec[0])
    } else {
        None
    }
}

pub fn lookup_ip_addr(ip_addr: &IpAddr) -> Option<String> {
    let names: Vec<String> = resolve_ip(ip_addr);
    if !names.is_empty() {
        Some(names[0].clone())
    } else {
        None
    }
}

pub async fn lookup_ip_addr_async(ip_addr: String) -> String {
    let ips: Vec<String> = resolve_ip_async(ip_addr).await;
    if !ips.is_empty() {
        ips[0].clone()
    } else {
        String::new()
    }
}

fn resolve_domain(host_name: String) -> Vec<IpAddr> {
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(_) => return Vec::new(),
    };
    rt.block_on(resolve_domain_async(host_name))
}

fn resolve_ip(ip_addr: &IpAddr) -> Vec<String> {
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(_) => return Vec::new(),
    };
    rt.block_on(resolve_ip_async(ip_addr.to_string()))
}

async fn resolve_domain_async(host_name: String) -> Vec<IpAddr> {
    let mut ips: Vec<IpAddr> = vec![];
    let Some(resolver) = get_resolver() else {
        return ips;
    };

    if let Ok(lip) = resolver.lookup_ip(host_name).await {
        for ip in lip.iter() {
            ips.push(ip);
        }
    }
    ips
}

async fn resolve_ip_async(ip_addr: String) -> Vec<String> {
    let ip_addr: IpAddr = match IpAddr::from_str(ip_addr.as_str()) {
        Ok(ip) => ip,
        Err(_) => return Vec::new(),
    };
    let mut names: Vec<String> = vec![];
    let Some(resolver) = get_resolver() else {
        return names;
    };

    let timeout = if crate::ip::is_global_addr(&ip_addr) {
        DEFAULT_TIMEOUT_GLOBAL
    } else {
        DEFAULT_TIMEOUT
    };

    let lookup_result = tokio::time::timeout(timeout, resolver.reverse_lookup(ip_addr)).await;
    if let Ok(Ok(rlookup)) = lookup_result {
        for name in rlookup.iter() {
            let s = name.to_string();
            if let Some(trimmed) = s.strip_suffix('.') {
                names.push(trimmed.to_string());
            } else {
                names.push(s);
            }
        }
    }

    names
}

pub async fn lookup_ips_async(ips: Vec<IpAddr>) -> HashMap<IpAddr, String> {
    let mut tasks = stream::iter(ips)
        .map(|ip| async move {
            let names = resolve_ip_async(ip.to_string()).await;
            (ip, names)
        })
        .buffer_unordered(10);
    let mut results: HashMap<IpAddr, String> = HashMap::new();
    while let Some(result) = tasks.next().await {
        results.insert(
            result.0,
            result.1.first().unwrap_or(&String::new()).to_string(),
        );
    }
    results
}

pub fn lookup_ips(ips: Vec<IpAddr>) -> HashMap<IpAddr, String> {
    let rt: tokio::runtime::Runtime = tokio::runtime::Runtime::new().unwrap();
    let handle = thread::spawn(move || rt.block_on(async { lookup_ips_async(ips).await }));
    handle.join().unwrap()
}

pub fn lookup_host(host: String) -> Vec<IpAddr> {
    resolve_domain(host)
}

pub fn lookup_addr(addr: &IpAddr) -> Vec<String> {
    resolve_ip(addr)
}
