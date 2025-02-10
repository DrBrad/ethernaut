#[derive(Debug)]
pub enum Types {
    IPv4,
    Arp,
    IPv6
}

impl Types {

    pub fn get_type_from_code(code: u16) -> Result<Self, String> {
        for c in [Self::IPv4, Self::Arp, Self::IPv6] {
            if c.get_code() == code {
                return Ok(c);
            }
        }

        Err(format!("Couldn't find for code: {}", code))
    }

    pub fn get_code(&self) -> u16 {
        match self {
            Self::IPv4 => 2048, //0800
            Self::Arp => 2054, //0806
            Self::IPv6 => 34525 //86dd
        }
    }
}

