# Automatically generated by pb2py
# fmt: off
import protobuf as p

if __debug__:
    try:
        from typing import Dict, List, Optional
        from typing_extensions import Literal  # noqa: F401
    except ImportError:
        Dict, List, Optional = None, None, None  # type: ignore


class BinanceCoin(p.MessageType):

    def __init__(
        self,
        amount: int = None,
        denom: str = None,
    ) -> None:
        self.amount = amount
        self.denom = denom

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('amount', p.SVarintType, 0),
            2: ('denom', p.UnicodeType, 0),
        }
