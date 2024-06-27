import sys
import warnings
from pathlib import Path

import pytest
import yara


@pytest.fixture(scope="session")
def rules_location():
    return get_rules_loc()


def get_rules_loc():
    return "/opt/yara/rules"


@pytest.fixture(scope="session")
def my_rules(rules_location):
    return get_my_rules(rules_location)


def get_my_rules(rules_loc):
    rules_dir = Path(rules_loc).absolute()
    rules_paths = rules_dir.rglob("*.yara")
    file_paths = {r.name: str(r) for r in rules_paths}

    rules = yara.compile(filepaths=file_paths)
    return rules


def get_sample_hashes(my_rules):
    test_data = {}
    for rule in my_rules:
        if rule.is_private:
            continue
        if "hashes" in rule.meta:
            for md5 in rule.meta["hashes"].split(","):
                md5 = md5.strip()
                if md5 in test_data:
                    test_data[md5].append(rule.identifier)
                else:
                    test_data[md5] = [rule.identifier]
        else:
            warnings.warn(
                f"Rule {rule.identifier} does not have a file example",
            )
    return test_data


def pytest_generate_tests(metafunc):
    params = []
    sample_hashes = get_sample_hashes(get_my_rules(get_rules_loc()))
    print(sample_hashes)
    for md5_hash in sample_hashes:
        params.append(
            pytest.param(
                md5_hash,
                sample_hashes[md5_hash],
                id=f"{md5_hash}-{sample_hashes[md5_hash]}",
            )
        )
    metafunc.parametrize("md5,expected_results", params)


class TestSignatures:

    malware_repo = "/malrepo"

    def get_malware_filepath(self, md5_hash):
        return Path(self.malware_repo, md5_hash[:4], md5_hash)

    def run_against_rules(self, md5_hash, expected, my_rules):

        filepath = self.get_malware_filepath(md5_hash)

        assert filepath.exists(), "File did not exist in the malware repo"

        assert filepath.is_file(), "Sample filepath is not a file"

        my_matches = my_rules.match(str(filepath))
        diff_res = set(expected).difference({x.rule for x in my_matches})

        assert (
            len(diff_res) == 0
        ), f"File did not hit on signature\nExpected: {expected} Actual: {my_matches}"

    def test_signatures(self, md5, expected_results, my_rules):
        self.run_against_rules(md5, expected_results, my_rules)


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:]))
