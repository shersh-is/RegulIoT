from dataclasses import dataclass

@dataclass
class Device:
    ip: str
    vendor: str
    product: str
    firmware: str | None
