use std::net::IpAddr;
use std::time::Duration;

#[cfg(not(any(unix, target_os = "windows")))]
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::Resolver;

use futures::stream::{self, StreamExt};

use hickory_resolver::AsyncResolver;
use std::collections::HashMap;
use std::str::FromStr;
use std::thread;

#[cfg(not(target_os = "windows"))]
const DEFAULT_TIMEOUT: Duration = Duration::from_millis(200);
#[cfg(not(target_os = "windows"))]
const DEFAULT_TIMEOUT_GLOBAL: Duration = Duration::from_millis(1000);
#[cfg(target_os = "windows")]
const DEFAULT_TIMEOUT: Duration = Duration::from_millis(20);
#[cfg(target_os = "windows")]
const DEFAULT_TIMEOUT_GLOBAL: Duration = Duration::from_millis(1000);

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
    if ipv6_vec.len() > 0 {
        return Some(ipv6_vec[0]);
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
    if ipv6_vec.len() > 0 {
        return Some(ipv6_vec[0]);
    } else {
        None
    }
}

pub fn lookup_ip_addr(ip_addr: &IpAddr) -> Option<String> {
    let names: Vec<String> = resolve_ip(ip_addr);
    if names.len() > 0 {
        return Some(names[0].clone());
    } else {
        return None;
    }
}

pub async fn lookup_ip_addr_async(ip_addr: String) -> String {
    let ips: Vec<String> = resolve_ip_async(ip_addr).await;
    if ips.len() > 0 {
        return ips[0].clone();
    } else {
        return String::new();
    }
}

#[cfg(any(unix, target_os = "windows"))]
fn resolve_domain(host_name: String) -> Vec<IpAddr> {
    let mut ips: Vec<IpAddr> = vec![];
    let resolver = Resolver::from_system_conf().unwrap();
    match resolver.lookup_ip(host_name) {
        Ok(lip) => {
            for ip in lip.iter() {
                ips.push(ip);
            }
        }
        Err(_) => {}
    }
    ips
}

#[cfg(not(any(unix, target_os = "windows")))]
fn resolve_domain(host_name: String) -> Vec<IpAddr> {
    let mut ips: Vec<IpAddr> = vec![];
    let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default()).unwrap();
    match resolver.lookup_ip(host_name) {
        Ok(lip) => {
            for ip in lip.iter() {
                ips.push(ip);
            }
        }
        Err(_) => {}
    }
    ips
}

#[cfg(any(unix, target_os = "windows"))]
fn resolve_ip(ip_addr: &IpAddr) -> Vec<String> {
    let mut names: Vec<String> = vec![];
    let mut system_conf = hickory_resolver::system_conf::read_system_conf().unwrap();
    if crate::ip::is_global_addr(ip_addr) {
        system_conf.1.timeout = DEFAULT_TIMEOUT_GLOBAL;
    } else {
        system_conf.1.timeout = DEFAULT_TIMEOUT;
    }
    let resolver = Resolver::new(system_conf.0, system_conf.1).unwrap();
    match resolver.reverse_lookup(*ip_addr) {
        Ok(rlookup) => {
            for record in rlookup.as_lookup().record_iter() {
                match record.data() {
                    Some(data) => {
                        let name = data.to_string();
                        if name.ends_with(".") {
                            names.push(name[0..name.len() - 1].to_string());
                        } else {
                            names.push(name);
                        }
                    }
                    None => {}
                }
            }
            names
        }
        Err(_) => {
            return names;
        }
    }
}

#[cfg(not(any(unix, target_os = "windows")))]
fn resolve_ip(ip_addr: IpAddr) -> Vec<String> {
    let mut names: Vec<String> = vec![];
    let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default()).unwrap();
    match resolver.reverse_lookup(ip_addr) {
        Ok(rlookup) => {
            for record in rlookup.as_lookup().record_iter() {
                match record.data() {
                    Some(data) => {
                        let name = data.to_string();
                        if name.ends_with(".") {
                            names.push(name[0..name.len() - 1].to_string());
                        } else {
                            names.push(name);
                        }
                    }
                    None => {}
                }
            }
            names
        }
        Err(_) => {
            return names;
        }
    }
}

#[cfg(any(unix, target_os = "windows"))]
async fn resolve_domain_async(host_name: String) -> Vec<IpAddr> {
    let mut ips: Vec<IpAddr> = vec![];
    let resolver = AsyncResolver::tokio_from_system_conf().unwrap();
    match resolver.lookup_ip(host_name).await {
        Ok(lip) => {
            for ip in lip.iter() {
                ips.push(ip);
            }
        }
        Err(_) => {}
    }
    ips
}

#[cfg(not(any(unix, target_os = "windows")))]
async fn resolve_domain_async(host_name: String) -> Vec<IpAddr> {
    let mut ips: Vec<IpAddr> = vec![];
    let resolver =
        AsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default()).unwrap();
    match resolver.lookup_ip(host_name).await {
        Ok(lip) => {
            for ip in lip.iter() {
                ips.push(ip);
            }
        }
        Err(_) => {}
    }
    ips
}

#[cfg(any(unix, target_os = "windows"))]
async fn resolve_ip_async(ip_addr: String) -> Vec<String> {
    let ip_addr: IpAddr = IpAddr::from_str(ip_addr.as_str()).unwrap();
    let mut names: Vec<String> = vec![];
    let mut system_conf = hickory_resolver::system_conf::read_system_conf().unwrap();
    if crate::ip::is_global_addr(&ip_addr) {
        system_conf.1.timeout = DEFAULT_TIMEOUT_GLOBAL;
    } else {
        system_conf.1.timeout = DEFAULT_TIMEOUT;
    }
    let resolver = AsyncResolver::tokio(system_conf.0, system_conf.1);
    match resolver.reverse_lookup(ip_addr).await {
        Ok(rlookup) => {
            for record in rlookup.as_lookup().record_iter() {
                match record.data() {
                    Some(data) => {
                        let name = data.to_string();
                        if name.ends_with(".") {
                            names.push(name[0..name.len() - 1].to_string());
                        } else {
                            names.push(name);
                        }
                    }
                    None => {}
                }
            }
            names
        }
        Err(_) => {
            return names;
        }
    }
}

#[cfg(not(any(unix, target_os = "windows")))]
async fn resolve_ip_async(ip_addr: String) -> Vec<String> {
    let mut names: Vec<String> = vec![];
    let resolver =
        AsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default()).unwrap();
    match resolver
        .reverse_lookup(IpAddr::from_str(ip_addr.as_str()).unwrap())
        .await
    {
        Ok(rlookup) => {
            for record in rlookup.as_lookup().record_iter() {
                match record.data() {
                    Some(data) => {
                        let name = data.to_string();
                        if name.ends_with(".") {
                            names.push(name[0..name.len() - 1].to_string());
                        } else {
                            names.push(name);
                        }
                    }
                    None => {}
                }
            }
            names
        }
        Err(_) => {
            return names;
        }
    }
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
