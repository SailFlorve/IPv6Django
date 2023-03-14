import dataclasses


@dataclasses.dataclass
class Constant:
    LIB_TREE_PATH = "lib/libtree"  # 6Tree的路径
    LIB_ZMAP_PATH = "zmap"  # zmap的路径

    TREE_DIR_PATH = "tree_hex"  # 6Tree的输出目录
    RESULT_DIR_PATH = "result"  # 结果目录名，例如任务结果一般存放在result/task_id/result，这两个result均为此变量
    TARGET_DIR_PATH = "targets"  # 生成的地址名，一般存放在result/task_id/targets，这两个result均为此变量

    PREPROCESS_DIR = f"preprocess"  # 生成的种子文件名
    SEEDS_NAME = f"seeds.txt"  # 生成的种子文件名
    SEEDS_PATH = f"{PREPROCESS_DIR}/{SEEDS_NAME}"  # 生成的种子文件路径
    TREE_INFO_NAME = "tree_info"
    VEC_SEQ_INFO_NAME = "vec_seq_info"
    POLICY_NAME = "policy.txt"
    MULTI_LEVEL_CLASSIFICATION_NAME = 'multi_level_classification.txt'

    UPLOAD_DIR_PATH = "upload"  # 上传文件的目录

    TARGET_TMP_PATH = "targets.txt"  # 用于保存6Tree的地址生成结果的临时文件名
    RESULT_TMP_PATH = "result.txt"  # 用于保存6Tree的探测结果的临时文件名
    TARGET_MERGE_NAME = 'targets_all.txt'

    DEFAULT_PORTS = "443"

    DEFAULT_BUDGET: int = 300000
    DEFAULT_PROBE = "icmp6_echoscan"

    LOG_FILE_NAME = "output_log.txt"
    SCAN_RES_NAME = "scan_result"  # nmap -oA的输出文件名

    ACTIVE_ADDR_FILE = "discovered_addrs"

    SCRIPT_DIR_PATH = '/usr/share/nmap/scripts'

    VULN_DB_VERSION_INITIAL = '0901.010000'
