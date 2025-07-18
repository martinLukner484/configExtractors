import struct
from sys import argv
from typing import BinaryIO, List, Optional

import pefile
from maco.extractor import Extractor
from maco.model import ExtractorModel


class TestExtractor(Extractor):
    family = "Test"
    author = "@martinLukner484"
    sharing: str = "TLP:CLEAR"
    yara_rule: str = """
rule test_matches_all {
  meta:
        description = "Only for testing purposes"
        author = "Martin Lukner"

  strings:
        $a = "*"
  condition:
	one of them
    }
"""

    def run(self, stream: BinaryIO, matches: List = None) -> Optional[ExtractorModel]:
        cfg = ExtractorModel(family="Test family")
        cfg.http.append(cfg.Http(uri="http://test.com"))
        return cfg


if __name__ == "__main__":
    parser = TestExtractor()
    file_path = argv[1]

    with open(file_path, "rb") as f:
        result = parser.run(f)
        if result:
            print(result.model_dump_json(indent=2, exclude_none=True, exclude_defaults=True))
        else:
            print("No configuration extracted")
