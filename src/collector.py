import logging

import requests
import vt
from pydantic import BaseModel
from pyquery import PyQuery as pq

from config import Bazaar, ETDA, VirusTotal
from feed import Feed

logger = logging.getLogger(__name__)


class Collector(BaseModel):
    _feeds: list[Feed] = []
    bazaar_cfg: Bazaar
    etda_cfg: ETDA
    vt_cfg: VirusTotal

    def _scrap_bazaar(self, url: str, data: dict[str, str]) -> None:
        # get response from MalwareBazaar API
        response = requests.post(url=url, data=data).json()
        if 'data' not in response.keys():
            logger.critical(f"can not get data from MalwareBazaar, response: {response}")
            exit(1)

        # create Feed instance with required hash values and optional signature value
        for malware in response['data']:
            self._feeds.append(Feed(
                md5=malware['md5_hash'],
                sha256=malware['sha256_hash'],
                malware_family=[] if malware['signature'] is None else [malware['signature']]
            ))

    def _scrap_etda(self, url: str) -> None:
        with requests.Session() as session:
            for feed in self._feeds:
                logger.info(f"start parsing '{feed.md5}' on etda")
                if len(feed.malware_family) == 0:
                    logger.warning("skipping, signature is None")
                    continue

                # search for a malware description with a signature from MalwareBazaar
                response = session.get(
                    f"{url}/cgi-bin/listtools.cgi?c=Malware&t=&x={feed.malware_family[0]}")
                html = pq(response.text)
                res = html('table').filter(lambda i: pq(this).find('h2').text() == 'Tools').find('a').filter(
                    lambda i: feed.malware_family[0].lower().replace(" ", "") in [name.lower().replace(" ", "") for name
                                                                                  in
                                                                                  pq(this).text().split(', ')])
                if len(res) == 0:
                    logger.warning(f"skipping, nothing found on etda with signature {feed.malware_family[0]}")
                    continue

                # get link to page with description
                try:
                    href = res[0].attrib['href']
                except KeyError:
                    logger.warning(f"skipping, no href found, response: {response}")
                    continue

                # add to 'malware_classes'
                response = session.get(
                    f"{url}{href}")
                html = pq(response.text)
                classes = html('td').filter(lambda i: pq(this).text() == 'Type').next().find('a')

                if len(classes) == 0:
                    logger.warning(f"skipping, no classes found, response: {response}")
                    continue

                for cls in classes:
                    feed.malware_class.append(cls.text)

    def _scrap_virustotal(self, api_key: str) -> None:
        with vt.Client(api_key) as client:
            for feed in self._feeds:
                logger.info(f"start parsing '{feed.md5}' on virustotal")
                try:
                    # get response from VirusTotal API for specific hash
                    response = client.get_json(f'/files/{feed.md5}')
                    logger.debug(f"response: {response}")

                    attr = response['data']['attributes']
                except (KeyError, ValueError, vt.APIError) as err:
                    logger.error(f"can not get required fields, error: {err}")
                    continue

                # add values to 'av_detects'
                try:
                    results = attr['last_analysis_results'].values()
                    for detect in results:
                        if detect['result'] is not None:
                            feed.av_detects.append(detect['result'])
                except (KeyError, ValueError) as err:
                    logger.error(f"can not set field 'av_detects', error: {err}")

                # add values to 'malware_class'
                try:
                    for cat in attr['popular_threat_classification']['popular_threat_category']:
                        feed.malware_class.append(cat['value'])
                except (KeyError, ValueError) as err:
                    logger.error(f"can not set field 'malware_class', error: {err}")

                # add values to 'malware_family'
                try:
                    for name in attr['popular_threat_classification']['popular_threat_name']:
                        feed.malware_family.append(name['value'])
                except (KeyError, ValueError) as err:
                    logger.error(f"can not set field 'malware_family', error: {err}")

    def run(self) -> list[Feed]:
        self._scrap_bazaar(self.bazaar_cfg.url, self.bazaar_cfg.data)
        self._scrap_etda(self.etda_cfg.url)
        self._scrap_virustotal(self.vt_cfg.api)

        return self._feeds
