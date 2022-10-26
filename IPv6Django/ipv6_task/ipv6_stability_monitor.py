import multiprocessing
import pathlib
import threading
import time
from typing import Callable

from IPv6Django import settings
from IPv6Django.bean.beans import IPv6TaskParams
from IPv6Django.constant.constant import Constant
from IPv6Django.ipv6_task.ipv6_task_base import IPv6TaskBase
from IPv6Django.tools.common_tools import Logger


class IPv6StabilityMonitor(IPv6TaskBase):
    def __init__(self, upload_file_path: pathlib.Path, work_path: pathlib.Path, ipv6_params: IPv6TaskParams):
        super(IPv6StabilityMonitor, self).__init__(work_path, upload_file_path)
        self.ipv6_params = ipv6_params

        self.current_time: int = 0

        self.on_single_monitor_finish_callback: Callable[[], None] = lambda: None
        self.std_out_callback = None

        self.work_thread = multiprocessing.Process(target=self.__monitor)

    def run(self):
        self.work_thread.start()

    def stop(self):
        self.process_executor.terminate()
        self.work_thread.terminate()

    def set_single_monitor_finish_callback(self, callback):
        self.on_single_monitor_finish_callback = callback

    # noinspection
    def __monitor(self):
        def __on_finish(ret_code):
            if ret_code != 0:
                self.stop()
                self.finished_callback(ret_code)
            else:
                self.on_single_monitor_finish_callback()
                Logger.log_to_file(f"IPv6StabilityMonitor: time {self.current_time} finished", path=self.work_path)

        times = self.ipv6_params.times

        for i in range(times):
            self.current_time = i + 1

            Logger.log_to_file(f"Start stability monitor time {self.current_time}", path=self.work_path)
            scanner_cmd = f"""zmap --probe-module={self.ipv6_params.probe} --ipv6-target-file={str(self.origin_file_path)} --output-file={str(self.work_path / Constant.RESULT_DIR_PATH / f"time_{self.current_time}")} --ipv6-source-ip={self.ipv6_params.ipv6} --rate={self.ipv6_params.rate} --cooldown-time=4 --verbosity=3"""
            if self.ipv6_params.probe != Constant.DEFAULT_PROBE:
                scanner_cmd += f" --target-port={self.ipv6_params.port}"

            # i == times - 1时阻塞调用
            ret_value = self.process_executor.execute(scanner_cmd,
                                                      finished_callback=None if i == times - 1 else __on_finish)

            if i == times - 1:
                __on_finish(ret_value[0])
                break

            Logger.log_to_file(f"Sleep {self.ipv6_params.interval} hours", path=self.work_path)
            if settings.DEBUG:
                sleep_time = self.ipv6_params.interval
            else:
                sleep_time = self.ipv6_params.interval * 60 * 60

            time.sleep(sleep_time)

        self.finished_callback(0)
        Logger.log_to_file("IPv6StabilityMonitor: thread exit", path=self.work_path)
