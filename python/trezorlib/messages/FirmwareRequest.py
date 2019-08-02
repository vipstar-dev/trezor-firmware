# Automatically generated by pb2py
# fmt: off
from .. import protobuf as p

if __debug__:
    try:
        from typing import Dict, List, Optional
        from typing_extensions import Literal  # noqa: F401
    except ImportError:
        Dict, List, Optional = None, None, None  # type: ignore


class FirmwareRequest(p.MessageType):
    MESSAGE_WIRE_TYPE = 8

    def __init__(
        self,
        offset: int = None,
        length: int = None,
    ) -> None:
        self.offset = offset
        self.length = length

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('offset', p.UVarintType, 0),
            2: ('length', p.UVarintType, 0),
        }
