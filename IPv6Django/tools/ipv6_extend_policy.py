import math
import pathlib
import threading
from dataclasses import dataclass
from typing import IO

from IPv6Django.constant.constant import Constant
from IPv6Django.tools.common_tools import Logger


@dataclass
class TreeNode:
    num: int
    inf: int
    sup: int
    parent_num: int
    children_num: int

    def get_range(self):
        return self.sup - self.inf


class Tree:
    def __init__(self, tree_path: pathlib.Path):
        self.tree_info_path = tree_path / Constant.TREE_INFO_NAME
        self.vec_seq_info_path = tree_path / Constant.VEC_SEQ_INFO_NAME
        self.tree_node_list: list[TreeNode] = []  # num, inf, sup, parent_num, children_num
        self.vec_seq_info: list[str] = []
        self.load()

    def load(self):
        with open(self.tree_info_path, "r") as f:
            for i, line in enumerate(f.readlines()):
                if i <= 2:
                    continue
                self.tree_node_list.append(TreeNode(*map(int, line.split(", "))))
        with open(self.vec_seq_info_path, "r") as f:
            self.vec_seq_info = [line.strip() for line in f.readlines()]


class IPv6ExtendPolicyGenerator:
    POLICY_SINGLE = 0
    POLICY_LIST = 1
    POLICY_RANGE = 2
    POLICY_WILDCARD = 3

    LARGE = "0"
    SMALL = "1"

    RANGE_T = 10  # 0 - 15
    ENTROPY_T = 0.7  # 4: 0.5 5: 0.58 6:0.64 7: 0.70 8: 0.75 9: 0.79 10: 0.83 12: 0.89
    TYPE_T = 10

    def __init__(self, work_path: pathlib.Path, tree_path: pathlib.Path):
        self.work_path = work_path
        self.tree = Tree(tree_path)
        self.output_path = work_path / Constant.PREPROCESS_DIR / Constant.POLICY_NAME
        self.output_path.parent.mkdir(exist_ok=True, parents=True)

        self.output_index: int = 0

        self.policy_map = {
            "111": self.POLICY_WILDCARD,
            "110": self.POLICY_LIST,
            "101": self.POLICY_RANGE,
            "100": self.POLICY_LIST,
            "011": self.POLICY_RANGE,
            "001": self.POLICY_LIST,
            "000": self.POLICY_LIST
        }

        self.thread = threading.Thread(target=self.__output_policy_thread)

    def output_policy(self):
        Logger.log_to_file("Start policy calculate", path=self.work_path)
        self.thread.start()

    def __output_policy_thread(self):
        f = open(self.output_path, "w+")

        for tree_node in self.tree.tree_node_list:
            if tree_node.children_num == 0:
                self.__output_policy_internal(f, tree_node)

        f.close()

        Logger.log_to_file("Policy calculate finished", path=self.work_path)

    def __output_policy_internal(self, f: IO, tree_node: TreeNode):

        addr_list: list[str] = self.tree.vec_seq_info[tree_node.inf:tree_node.sup + 1]
        if len(addr_list) == 0 or len(addr_list) == 1:
            return

        self.output_index += 1
        f.write(f"Policy Group {self.output_index}\n")
        f.write("=====================================\n")

        bytes_list_dict: dict[int, list[int]] = {}

        for addr in addr_list:
            f.write(f"{addr}\n")
            for i in range(0, 32):
                if i not in bytes_list_dict:
                    bytes_list_dict[i] = [int(addr[i], 16)]
                else:
                    bytes_list_dict[i].append(int(addr[i], 16))

        for i in range(0, 32):
            bytes_list = bytes_list_dict[i]
            p_range, p_entropy, p_types = IPv6ExtendPolicyGenerator.__get_statistic_result(bytes_list)
            policy_express = self.__get_policy_express(bytes_list, p_range, p_entropy, p_types)
            f.write(f"{policy_express}")
        f.write("\n\n")

    @staticmethod
    def __get_statistic_result(bytes_list: list[int]) -> (int, int, int):
        p_range = max(bytes_list) - min(bytes_list)

        p_entropy = 0
        for i in range(0, 16):
            count = bytes_list.count(i)
            if count == 0:
                continue
            p_entropy += count / len(bytes_list) * math.log(count / len(bytes_list), 16)
        p_entropy = -p_entropy

        p_types = len(set(bytes_list))

        return p_range, p_entropy, p_types

    def __get_policy_express(self, bytes_list, p_range: int, p_entropy: int, p_types: int) -> str:
        if p_range == 0 and p_entropy == 0 and p_types == 1:
            return f"[{self.__hex(bytes_list[0])}]"

        range_flag = self.LARGE if p_range >= self.RANGE_T else self.SMALL
        entropy_flag = self.LARGE if p_entropy >= self.ENTROPY_T else self.SMALL
        type_flag = self.LARGE if p_types >= self.TYPE_T else self.SMALL

        policy = self.policy_map[range_flag + entropy_flag + type_flag]

        match policy:
            case self.POLICY_WILDCARD:
                return "[*]"
            case self.POLICY_LIST:
                return f"[{','.join(map(self.__hex, bytes_list))}]"
            case self.POLICY_RANGE:
                return f"[{self.__hex(min(bytes_list))}-{self.__hex(max(bytes_list))}]"
        return "[]"

    @staticmethod
    def __hex(num: int) -> str:
        return hex(num)[2:]


if __name__ == '__main__':
    IPv6ExtendPolicyGenerator.__get_statistic_result([1, 2, 3, 4, 5])
