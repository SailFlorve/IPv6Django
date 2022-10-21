class CommandParser:
    """
    解析库输出的命令，从中判断当前类型、进度并提取关键信息
    """

    TYPE_START = 4
    TYPE_FINISH = 3
    TYPE_BUDGET = 2
    TYPE_SENDING = 1
    TYPE_OTHER = 0
    TYPE_ZMAP_START = 5

    TYPE_6TREE_START = 10
    TYPE_6TREE_TRANS = 11
    TYPE_6TREE_TRANS_FINISH = 12

    def __init__(self):
        pass

    def parse(self, msg) -> (int, str):
        try:
            return self.__parse_try(msg)
        except Exception as e:
            print(e)
            return self.TYPE_OTHER, ""

    def __parse_try(self, msg) -> (int, list):
        msg = msg.strip()  # 命令
        info = []  # 解析出来的数据

        if "--ipv6-target-file" in msg:
            msg_type = self.TYPE_ZMAP_START

        elif "send" in msg and "recv" in msg and "hitrate" in msg:
            msg_type = self.TYPE_SENDING
            current = msg.split("send: ")[-1].split(" ")[0]
            # parseMsg = f"活动地址探测: {current} / {self.lastLineCount}"
            hit_rate: str = msg.split("hitrate: ")[-1].split(" ")[0]
            hit_rate: float = float(hit_rate.strip("%"))  # 获得当前命中率
            info.append(int(current))
            info.append(hit_rate)

        elif "budget remains:" in msg:
            msg_type = self.TYPE_BUDGET
            budget = int(msg.split('budget remains: ')[-1])
            info.append(int(budget))
        elif "Find total active addresses" in msg or "Total scanning finished" in msg:
            msg_type = self.TYPE_FINISH
            total_active = msg.split("Find total active addresses: ")[-1].split("\n")[0]
            # allGenerate = self.allBudget - self.budget
            # parseMsg = f"找到活动地址: {total_active}, 已扩展: {allGenerate}, 命中率: {int(total_active) / allGenerate}"
            if total_active.isdecimal():
                info.append(int(total_active))
            else:
                info.append(0)
        elif "Read scanner parameters finished" in msg:
            msg_type = self.TYPE_6TREE_START
            # parseMsg = f"剩余预算: {self.allBudget}"
        elif "Start translation" in msg:
            msg_type = self.TYPE_6TREE_TRANS
            # parseMsg = "状态: 正在预处理..."
        elif "Space tree generation finished" in msg:
            msg_type = self.TYPE_6TREE_TRANS_FINISH
            # parseMsg = "状态: 地址预处理完成"
        else:
            msg_type = self.TYPE_OTHER
            # parseMsg = ""

        return msg_type, info


if __name__ == '__main__':
    h = "11.88%"
    print(h.strip("%"))
