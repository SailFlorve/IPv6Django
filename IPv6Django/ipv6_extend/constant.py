import dataclasses


@dataclasses.dataclass
class Constant:
    LIB_TREE_PATH = "lib/6tree_mod_2"
    LIB_ZMAP_PATH = "zmap"

    TREE_DIR_PATH = "tree_hex"
    RESULT_DIR_PATH = "result"

    SEEDS_NAME = f"seeds_hex"

    UPLOAD_DIR_PATH = "upload"

    TARGET_DIR_PATH = "targets"
    TARGET_TMP_PATH = "targets.txt"
    RESULT_TMP_PATH = "result.txt"

    DEFAULT_PORTS = "443"

    DEFAULT_BUDGET: int = 300000
    DEFAULT_PROBE = "icmp6_echoscan"

    LOG_FILE_NAME = "output_log.txt"
    SCAN_RES_NAME = "scan_result"

    ACTIVE_ADDR_FILE = "discovered_addrs"

