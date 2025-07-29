import struct
import binascii
import re
from maco.extractor import Extractor
from maco.model import ExtractorModel
from typing import BinaryIO, List, Optional

def _decompress_lznt1_chunk(chunk):
    out = bytes()
    while chunk:
        flags = ord(chunk[0:1])
        chunk = chunk[1:]
        for i in range(8):
            if not (flags >> i & 1):
                out += chunk[0:1]
                chunk = chunk[1:]
            else:
                flag = struct.unpack('<H', chunk[:2])[0]
                pos = len(out) - 1
                l_mask = 0xFFF
                o_shift = 12
                while pos >= 0x10:
                    l_mask >>= 1
                    o_shift -= 1
                    pos >>= 1

                length = (flag & l_mask) + 3
                offset = (flag >> o_shift) + 1

                if length >= offset:
                    tmp = out[-offset:] * int(0xFFF / len(out[-offset:]) + 1)
                    out += tmp[:length]
                else:
                    out += out[-offset:-offset+length]
                chunk = chunk[2:]
            if len(chunk) == 0:
                break
    return out

def decompress_lznt1(buf, length_check=True):
    out = bytes()
    while buf:
        header = struct.unpack('<H', buf[:2])[0]
        length = (header & 0xFFF) + 1
        if length_check and length > len(buf[2:]):
            raise ValueError('invalid chunk length')
        else:
            chunk = buf[2:2+length]
            if header & 0x8000:
                out += _decompress_lznt1_chunk(chunk)
            else:
                out += chunk
        buf = buf[2+length:]

    return out

class ToughprogressParser(Extractor):
    family = "Toughprogress"
    author = "Martin Lukner"
    last_modified = "2025-07-23"
    sharing: str = "TLP:CLEAR"
    yara_rule: str = """
        rule testRule {
            meta:
                description = "Just for testing purposes"
                author = "Martin Lukner"

            strings:
                $s = {ee ec ab cf}

            condition:
                all of them 
            }
        """

    def decode_self(self, content, payload_base, payload_size):
        intermediate_stage = []
        for i in range(payload_size):
            intermediate_stage.append(content[payload_base + i] ^ content[(payload_base - 0x10) + (i & 0xF)])
        return bytes(intermediate_stage)


    def run(self, stream: BinaryIO, matches:List = []) -> Optional[ExtractorModel]:
        content = stream.read()
        payload_size = struct.unpack('<L', content[3:7])[0]
        payload_base = len(content) - payload_size
        intermediate_stage = self.decode_self(content, payload_base, payload_size)
        match = re.search(b'\x4c\x8d.(....)..\x41\x8b.\x01\x41\xb8\x00\x10\x00\x00\x41\x8b.\x05', intermediate_stage)
        config_address = struct.unpack('<L', match.group(1))[0] + match.start() + payload_base + 7
        cfg = ExtractorModel(family=self.family)
        cfg.binaries.append(cfg.Binary(data="Test", other={"Type": "Intermediate Stage", "MD5": "Blah"}))
        cfg.paths.append(cfg.Path(path="Testpath", usage=cfg.Path.UsageEnum.other))
        offset_compressed_payload = struct.unpack('<L', intermediate_stage[config_address + 0xD - payload_base:config_address + 0xD + 4 - payload_base])[0] + config_address
        size_uncompressed_payload = struct.unpack('<L', intermediate_stage[config_address + 0x5 - payload_base:config_address + 0x5 + 4 - payload_base])[0] 
        size_compressed_payload = struct.unpack('<L', intermediate_stage[config_address + 0x9 - payload_base:config_address + 0x9 + 4 - payload_base])[0] 
        print(f"Config_address: {hex(config_address)}, Compressed Payload: {hex(offset_compressed_payload)}, Size compressed: {hex(size_compressed_payload)}, Size uncompressed: {hex(size_uncompressed_payload)}")
        decompressed = decompress_lznt1(intermediate_stage[offset_compressed_payload - payload_base: offset_compressed_payload - payload_base + size_compressed_payload])
        return cfg

if __name__ == "__main__":
    parser = ToughprogressParser()
    file_path = argv[1]
    with open(file_path, 'rb') as f:
        result = parser.run(f)
        if result:
            print(result.model_dump_json(indent=2, exclude_none=True, exclude_defaults=True))
        else:
            print("No configuration extracted!")
