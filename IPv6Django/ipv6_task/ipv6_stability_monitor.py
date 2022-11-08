import multiprocessing
import pathlib
import time
from typing import Callable

from IPv6Django.bean.beans import IPv6TaskParams
from IPv6Django.constant.constant import Constant
from IPv6Django.ipv6_task.ipv6_task_base import IPv6TaskBase
from IPv6Django.models import IPv6TaskModel
from IPv6Django.tools.logger import Logger


class IPv6StabilityMonitor(IPv6TaskBase):
    def __init__(self, upload_file_path: pathlib.Path, work_path: pathlib.Path, ipv6_params: IPv6TaskParams):
        super(IPv6StabilityMonitor, self).__init__(work_path, upload_file_path)
        self.ipv6_params = ipv6_params

        self.current_time: int = 0

        self.on_single_monitor_finish_callback: Callable[[], None] = lambda: None
        self.std_out_callback = None

        self.work_thread = multiprocessing.Process(target=self.__monitor)

        self.is_monitoring: bool = False

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
            self.is_monitoring = False
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

            self.is_monitoring = True
            # i == times - 1时阻塞调用
            ret_value = self.process_executor.execute(scanner_cmd,
                                                      finished_callback=None if i == times - 1 else __on_finish)

            if i == times - 1:
                __on_finish(ret_value[0])
                break

            interval = self.ipv6_params.interval
            unit = self.ipv6_params.interval_unit

            match unit:
                case IPv6TaskModel.INTERVAL_UNIT_HOUR:
                    sleep_time = interval * 60 * 60
                case IPv6TaskModel.INTERVAL_UNIT_MINUTE:
                    sleep_time = interval * 60
                case IPv6TaskModel.INTERVAL_UNIT_SECOND:
                    sleep_time = interval
                case _:
                    raise Exception("Unknown interval unit")

            Logger.log_to_file(f"Sleep {sleep_time} seconds", path=self.work_path)

            while sleep_time > 0:
                sleep_unit = 60 if sleep_time > 60 else sleep_time
                time.sleep(sleep_unit)
                sleep_time -= sleep_unit

            if self.is_monitoring:
                Logger.log_to_file(f"Sleep finished. Task still running, waiting...", path=self.work_path)

            while self.is_monitoring:
                time.sleep(5)

        self.finished_callback(0)
        Logger.log_to_file("IPv6StabilityMonitor: thread exit", path=self.work_path)
