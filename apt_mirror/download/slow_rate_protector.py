# SPDX-License-Identifier: GPL-3.0-or-later

from abc import ABCMeta, abstractmethod
from datetime import datetime, timedelta
from typing import Any

from .format import format_size


class SlowRateException(RuntimeError):
    def __init__(self, target: str, rate: str, *args: object) -> None:
        super().__init__(f"Slow rate for `{target}`: {rate}", *args)


class BaseSlowRateProtector(metaclass=ABCMeta):
    @abstractmethod
    def rate(self, count: int): ...

    def pause(self, delta: timedelta) -> None:  # noqa: B027
        pass


class DummySlowRateProtector(BaseSlowRateProtector):
    def rate(self, count: int):
        return


class SlowRateProtector(BaseSlowRateProtector):
    def __init__(self, target: Any, rate_startup: int, slow_rate: int) -> None:
        self._startup = datetime.now()

        self._target = target
        self._rate_startup = rate_startup
        self._slow_rate = slow_rate

        self._count = 0

    def pause(self, delta: timedelta) -> None:
        if delta.total_seconds() > 0:
            self._startup += delta

    def rate(self, count: int):
        passed = int((datetime.now() - self._startup).total_seconds())
        self._count += count

        if passed <= 0 or passed < self._rate_startup:
            return

        rate = self._count / passed

        if rate < self._slow_rate:
            raise SlowRateException(self._target, f"{format_size(rate)}/sec")


class SlowRateProtectorFactory:
    def __init__(self, enabled: bool, rate_startup: int, slow_rate: int) -> None:
        self._enabled = enabled
        self._rate_startup = rate_startup
        self._slow_rate = slow_rate

    def for_target(self, target: Any) -> BaseSlowRateProtector:
        if not self._enabled:
            return DummySlowRateProtector()

        return SlowRateProtector(target, self._rate_startup, self._slow_rate)
