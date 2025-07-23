from maco.extractor import Extractor
from maco.model import ConnUsageEnum, ExtractorModel

class TestMalware(Extractor):
    family = "Test Family"
    author = "Martin Lukner"
    last_modified = "2025-07-23"
    sharing: str = "TLP:CLEAR"
    yara_rule: str = """
    rule testRule {
    meta:
        description = "Just for testing purposes"
        author = "Martin Lukner"

    strings:
        $s = "Test" ascii wide

    condition:
        all of them 
}
"""

    def run(self, stream: BinaryIO, matches: List = []) -> Optional[ExtractorModel]:
                cfg.other = "Test result"
                return cfg


if __name__ == "__main__":
    parser = TestMalware()
    file_path = argv[1]

    with open(file_path, "rb") as f:
        result = parser.run(f)
        if result:
            print(result.model_dump_json(indent=2, exclude_none=True, exclude_defaults=True))
        else:
            print("No configuration extracted")
