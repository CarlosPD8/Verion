from functools import lru_cache
from typing import Annotated

from fastapi import Depends

from verion.platform.clock import SystemClock
from verion.platform.id_generator import UuidIdGenerator
from verion.shared_kernel.ports import ClockPort, IdGeneratorPort


@lru_cache
def get_clock() -> ClockPort:
    return SystemClock()


@lru_cache
def get_id_generator() -> IdGeneratorPort:
    return UuidIdGenerator()


ClockDep = Annotated[ClockPort, Depends(get_clock)]
IdGeneratorDep = Annotated[IdGeneratorPort, Depends(get_id_generator)]
