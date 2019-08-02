# Automatically generated by pb2py
# fmt: off
from .. import protobuf as p

if __debug__:
    try:
        from typing import Dict, List, Optional
        from typing_extensions import Literal  # noqa: F401
    except ImportError:
        Dict, List, Optional = None, None, None  # type: ignore


class FirmwareErase(p.MessageType):
    MESSAGE_WIRE_TYPE = 6

    def __init__(
        self,
        length: int = None,
    ) -> None:
        self.length = length

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('length', p.UVarintType, 0),
        }
