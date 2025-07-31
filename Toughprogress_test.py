import struct
import re

FILE_PATH = "/home/user/Downloads/image/6.jpg"

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

def get_null_terminated_string(data, begin):
    i = begin
    result = ""
    while data[i] != 0:
        print(data[i])
        result = result + chr(data[i])
        i = i + 1
    return result
    
def xor_decode(data, addr, length):
    result = []
    for i in range(length):
        result.append(data[addr + i] ^ data[(addr - 0x10) + (i & 0xf)])
    return bytes(result)
    
def find_matching_section(data):
    peHeader = struct.unpack('<H', data[0x3c:0x3c + 2])[0]
    sizeOfOptionalHeader = struct.unpack('<H', data[peHeader + 0x14:peHeader + 0x14 + 2])[0]
    sectionHeader = peHeader + 0x18 + sizeOfOptionalHeader
    numberOfSections = struct.unpack('<H', data[peHeader + 0x6:peHeader + 0x6 + 2])[0]
    for i in range(numberOfSections):
        address = struct.unpack('<L', data[sectionHeader + i * 0x28 + 0x14:sectionHeader + i * 0x28 + 0x14 + 4])[0]
        size = struct.unpack('<L', data[sectionHeader + i * 0x28 + 0x8:sectionHeader + i * 0x28 + 0x8 + 4])[0]
        lastField = struct.unpack('<L', data[address + size - 4:address + size])[0]
        print(f"Section: {i}, address: {hex(address)}, size: {hex(size)}, last 4 bytes: {hex(lastField)}")
        if lastField < size - 4:
            seed = struct.unpack('<L', data[address + size - lastField + 3:address + size - lastField + 7])[0]
            index = 0
            while data[index + sectionHeader + i * 0x28] != 0:
                seed = seed * 0x21 + data[index + sectionHeader + i * 0x28] & 0xFFFFFFFF
                index = index + 1
            if seed == struct.unpack('<L', data[address + size - lastField + 0x7:address + size - lastField + 0xB])[0]:
                return (address, size, lastField)
   
class Stage:
    def __init__(self, data):
        self.data = data
        self.find_config()
        self.extract_config()
        self.decompress_contained_stage()
        
    def find_config(self):
        REGEX = b'.\x8d.{1,2}(....)(\x33\xc9).{2,3}\x01\x41\xb8\x00\x10\x00\x00.{2,3}\x05'
        match = re.search(REGEX, self.data)
        return match
        
    def extract_config(self):
        match = self.find_config()
        self.config_address = struct.unpack('<L', match.group(1))[0] + match.start() + match.span(1)[0] -  match.start() + 4
        offset_compressed_payload = struct.unpack('<L', self.data[self.config_address + 0xD:self.config_address + 0xD + 4])[0] + self.config_address
        size_uncompressed_payload = struct.unpack('<L', self.data[self.config_address + 0x5:self.config_address + 0x5 + 4])[0] 
        size_compressed_payload = struct.unpack('<L', self.data[self.config_address + 0x9:self.config_address + 0x9 + 4])[0] 
        self.offset_compressed_payload = offset_compressed_payload
        self.size_uncompressed_payload = size_uncompressed_payload
        self.size_compressed_payload = size_compressed_payload
        
    def decompress_contained_stage(self):
        self.next_stage = decompress_lznt1(self.data[self.offset_compressed_payload:self.offset_compressed_payload + self.size_compressed_payload])
        
with open(FILE_PATH, 'rb') as f:
	content = f.read()
first_stage_size = struct.unpack('<L', content[3:7])[0]
first_stage_base = len(content) - first_stage_size
first_stage_data = xor_decode(content, first_stage_base, first_stage_size)
first_stage_data = first_stage_data[0x28:]
first_stage = Stage(first_stage_data)  
path = get_null_terminated_string(first_stage_data, first_stage.config_address + 0x11)
print(path)

second_stage_data = first_stage.next_stage
(address, size, lastField) = find_matching_section(second_stage_data)
second_stage_size = struct.unpack('<L', second_stage_data[address + size - lastField - 1: address + size - lastField + 3])[0]
second_stage_base = address + size - second_stage_size - 4

print(f"size: {hex(second_stage_size)}, second_stage_base: {hex(second_stage_data[second_stage_base])}")
second_stage_data = xor_decode(second_stage_data, second_stage_base, second_stage_size)
second_stage = Stage(second_stage_data)
