import yaml
from pydantic_settings import BaseSettings


class Bazaar(BaseSettings):
    url: str
    data: dict[str, str]


class ETDA(BaseSettings):
    url: str
    mapping: dict[str, str]


class VirusTotal(BaseSettings):
    api: str
    mapping: dict[str, str]


class ThreatLevel(BaseSettings):
    definition: dict[int, str]
    mapping: dict[str, int]


# class represents configuration file
class Config(BaseSettings):
    bazaar: Bazaar
    etda: ETDA
    virustotal: VirusTotal
    threat_level: ThreatLevel
    logger: dict

    @staticmethod
    def load(path: str) -> 'Config':
        with open(path) as f:
            yaml_cfg = yaml.safe_load(f)
        return Config(**yaml_cfg)
