pub struct Registry;
pub fn parse_name(value: &str) -> &str { value.trim() }
impl Registry { pub fn find<'a>(&self, name: &'a str) -> &'a str { parse_name(name) } }
