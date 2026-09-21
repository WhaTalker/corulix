class Registry:
    def find(self, name: str) -> str:
        return parse_name(name)

def parse_name(value: str) -> str:
    return value.strip()
