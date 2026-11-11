"""
Protocol Message Formats and Packet Serialization.
Defines schemas for Handshake (ClientHello, ServerHello), Encrypted Telemetry, and ACKs.
"""

import json
from dataclasses import dataclass, asdict
from typing import Dict, Any

@dataclass
class ClientHelloMessage:
    node_id: str
    client_nonce_hex: str
    timestamp: float
    ephemeral_pubkey_hex: str
    identity_cert: Dict[str, Any]
    signature_hex: str

    def get_signed_payload_bytes(self) -> bytes:
        data = f"{self.node_id}:{self.client_nonce_hex}:{self.timestamp}:{self.ephemeral_pubkey_hex}"
        return data.encode("utf-8")

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @classmethod
    def from_json(cls, data_str: str) -> "ClientHelloMessage":
        return cls(**json.loads(data_str))


@dataclass
class ServerHelloMessage:
    server_id: str
    server_nonce_hex: str
    timestamp: float
    ephemeral_pubkey_hex: str
    identity_cert: Dict[str, Any]
    signature_hex: str

    def get_signed_payload_bytes(self, client_nonce_hex: str) -> bytes:
        data = f"{self.server_id}:{self.server_nonce_hex}:{self.timestamp}:{self.ephemeral_pubkey_hex}:{client_nonce_hex}"
        return data.encode("utf-8")

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @classmethod
    def from_json(cls, data_str: str) -> "ServerHelloMessage":
        return cls(**json.loads(data_str))


@dataclass
class TelemetryHeader:
    node_id: str
    session_id: str
    sequence_num: int
    timestamp: float
    iv_hex: str

    def to_aad_bytes(self) -> bytes:
        """Serializes header deterministically to serve as Associated Authenticated Data (AAD)."""
        data = f"{self.node_id}:{self.session_id}:{self.sequence_num}:{self.timestamp}:{self.iv_hex}"
        return data.encode("utf-8")


@dataclass
class TelemetryPacket:
    header: TelemetryHeader
    ciphertext_hex: str  # Contains AES-GCM ciphertext + 16-byte authentication tag

    def to_dict(self) -> Dict[str, Any]:
        return {
            "header": asdict(self.header),
            "ciphertext_hex": self.ciphertext_hex
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "TelemetryPacket":
        header = TelemetryHeader(**d["header"])
        return cls(header=header, ciphertext_hex=d["ciphertext_hex"])

    @classmethod
    def from_json(cls, data_str: str) -> "TelemetryPacket":
        return cls.from_dict(json.loads(data_str))


@dataclass
class AckPacket:
    node_id: str
    session_id: str
    ack_sequence_num: int
    status: str
    timestamp: float

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @classmethod
    def from_json(cls, data_str: str) -> "AckPacket":
        return cls(**json.loads(data_str))
