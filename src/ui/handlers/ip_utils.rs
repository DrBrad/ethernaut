use std::net::{IpAddr, Ipv4Addr};
use crate::database::sqlite::Database;
use crate::ui::handlers::net_mask::NetMask;

const LOCAL_BROADCAST: [u8; 4] = [0xff, 0xff, 0xff, 0xff];
const V4_MAPPED: NetMask = NetMask {
    address: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00],
    mask: 96,
};

pub fn ip_to_code(db: &Database, address: IpAddr) -> Option<String> {
    if match address {
        IpAddr::V4(v4) => {
            v4.is_private() ||
                v4.is_loopback() ||
                v4.is_link_local()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback() // ::1
                || v6.is_unspecified() // :: (unspecified)
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // fc00::/7 (ULA)
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // fe80::/10 (Link-local)
        }
    } {
        return None;
    }

    match address {
        IpAddr::V4(address) => {
            let address = u32::from(address);
            Some(db.get(
                "ipv4_location",
                Some(vec!["id", "country_code"]),
                Some(format!("start <= {} AND end >= {}", address, address).as_str())
            ).get(0).unwrap().get("country_code").unwrap().to_string())
        }
        IpAddr::V6(address) => {
            None
        }
    }
}

pub fn is_teredo(addr: IpAddr) -> bool {
    if let IpAddr::V6(v6) = addr {
        let octets = v6.octets();
        return octets[0] == 0x20 && octets[1] == 0x01 && octets[2] == 0x00 && octets[3] == 0x00;
    }

    false
}

pub fn is_global_unicast(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            if v4.octets()[0] == 0 || v4.octets() == LOCAL_BROADCAST {
                return false;
            }
        }
        IpAddr::V6(v6) => {
            if (v6.segments()[0] & 0xfe) == 0xfc || V4_MAPPED.contains(addr)/* || v6.is_ipv4_compatible()*/ {
                // || ((Inet6Address) address).isIPv4CompatibleAddress())
                return false;
            }
        }
    }

    match addr {
        IpAddr::V4(v4) => {
            !(v4.is_unspecified() || v4.is_loopback() || v4.is_link_local() || v4.is_multicast() || v4.is_broadcast())
        }
        IpAddr::V6(v6) => {
            !(v6.is_unspecified() || v6.is_loopback()/* || v6.is_unicast_link_local()*/ || v6.is_multicast()/* || v6.is_unicast_site_local()*/)
        }
    }
}
