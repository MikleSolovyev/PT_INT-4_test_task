from pydantic import BaseModel


# class represents feed model
class Feed(BaseModel):
    md5: str
    sha256: str
    malware_class: list[str] = []
    malware_family: list[str] = []
    av_detects: list[str] = []
    threat_level: str = ''
