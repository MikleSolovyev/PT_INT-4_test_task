from pydantic import BaseModel

from feed import Feed


class Analyzer(BaseModel):
    feeds: list[Feed]
    defs: dict[int, str]
    mapping: dict[str, int]

    def run(self) -> None:
        for feed in self.feeds:
            # threat level is the maximum of all malware classes threat levels
            max_level = max([self.mapping[mlw_cls] for mlw_cls in feed.malware_class], default=0)

            feed.threat_level = self.defs[max_level]
