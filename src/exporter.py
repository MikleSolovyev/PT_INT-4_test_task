from pydantic import BaseModel

from feed import Feed


class Exporter(BaseModel):
    feeds: list[Feed]

    def run(self) -> None:
        for feed in self.feeds:
            # for pretty output put indent=4 inside model_dump_json()
            print(feed.model_dump_json())
