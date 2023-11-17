import logging.config

from analyzer import Analyzer
from collector import Collector
from combiner import Combiner
from config import Config
from exporter import Exporter

CONFIG_PATH = 'config/config.yaml'

logger = logging.getLogger(__name__)

if __name__ == '__main__':
    # parse config
    cfg = Config.load(CONFIG_PATH)

    # setup logger
    logging.config.dictConfig(cfg.logger)
    logger.info("config successfully parsed and logger configured")

    # run collector module
    logger.info("starting collector")
    feeds = Collector(
        bazaar_cfg=cfg.bazaar,
        etda_cfg=cfg.etda,
        vt_cfg=cfg.virustotal
    ).run()

    # run combiner module
    logger.info("starting combiner")
    Combiner(
        feeds=feeds,
        etda_mapping=cfg.etda.mapping,
        vt_mapping=cfg.virustotal.mapping
    ).run()

    # run analyzer module
    logger.info("starting analyzer")
    Analyzer(
        feeds=feeds,
        defs=cfg.threat_level.definition,
        mapping=cfg.threat_level.mapping
    ).run()

    # run exporter module
    logger.info("starting exporter")
    Exporter(feeds=feeds).run()
