#[macro_use]
extern crate log;

mod interface;
mod ipv4;
mod icmp;
mod tcp;
mod udp;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
