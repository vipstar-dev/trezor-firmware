# Automatically generated by pb2py
import protobuf as p


class CipheredKeyValue(p.MessageType):
    MESSAGE_WIRE_TYPE = 48
    FIELDS = {
        1: ('value', p.BytesType, 0),
    }

    def __init__(
        self,
        value: bytes = None
    ) -> None:
        self.value = value