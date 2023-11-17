from pydantic import BaseModel

from feed import Feed


class Combiner(BaseModel):
    feeds: list[Feed]
    etda_mapping: dict[str, str]
    vt_mapping: dict[str, str]

    def _combine_malware_class(self) -> None:
        for feed in self.feeds:
            combine_set: set[str] = set()

            # map and delete repeats
            for mlw_cls in feed.malware_class:
                if mlw_cls in self.etda_mapping.keys():
                    combine_set.add(self.etda_mapping[mlw_cls])
                elif mlw_cls in self.vt_mapping.keys():
                    combine_set.add(self.vt_mapping[mlw_cls])

            # delete common classes such as Trojan, Worm, Flooder if more specific classes exist
            trojan_cnt = 0
            worm_cnt = 0
            flooder_cnt = 0
            for mlw_cls in combine_set:
                if 'Trojan' in mlw_cls:
                    trojan_cnt += 1
                if 'Worm' in mlw_cls:
                    worm_cnt += 1
                if 'Flooder' in mlw_cls:
                    flooder_cnt += 1

            if trojan_cnt > 1 and 'Trojan' in combine_set:
                combine_set.remove('Trojan')
            if worm_cnt > 1 and 'Worm' in combine_set:
                combine_set.remove('Worm')
            if flooder_cnt > 1 and 'Flooder' in combine_set:
                combine_set.remove('Flooder')

            feed.malware_class = list(combine_set)

    def _combine_malware_family(self) -> None:
        for feed in self.feeds:
            result: list[str] = []
            combine_set: set[str] = set()

            # delete repeats even if different case
            for family in feed.malware_family:
                if family.lower() not in combine_set:
                    result.append(family)
                combine_set.add(family.lower())

            feed.malware_family = result

    def _combine_av_detects(self) -> None:
        for feed in self.feeds:
            # delete repeats
            feed.av_detects = list(set(feed.av_detects))

    def run(self) -> None:
        self._combine_malware_class()
        self._combine_malware_family()
        self._combine_av_detects()
