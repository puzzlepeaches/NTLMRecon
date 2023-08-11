import re
import random
from iptools import IpRangeList

CIDR_REGEX = re.compile(r"^([0-9]{1,3}\.){3}[0-9]{1,3}(\/([0-9]|[1-2][0-9]|3[0-2]))?$")
URL_REGEX = re.compile(
    r"^(?:http(s)?:\/\/)?[\w.-]+(?:\.[\w\.-]+)+[\w\-\._~:/?#[\]@!\$&'\(\)\*\+,;=.]+$"
)
HOST_REGEX = re.compile(
    r"^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$"
)


def _cidr_to_iplist(cidr):
    try:
        ip_range = IpRangeList(cidr)
        return ["https://" + str(x) for x in ip_range]
    except Exception as e:
        print(f"[!] That's not a valid IP address or CIDR: {e}")
        return []


def _identify_and_return_records(inputstr):
    if CIDR_REGEX.match(inputstr):
        return _cidr_to_iplist(inputstr)
    elif URL_REGEX.match(inputstr):
        if not (inputstr.startswith("http://") or inputstr.startswith("https://")):
            inputstr = "https://" + inputstr
        return [inputstr]
    elif HOST_REGEX.match(inputstr):
        return ["https://" + inputstr]
    return []


def readfile_and_gen_input(file, shuffle=False):
    master_records = []
    try:
        with open(file, "r") as fr:
            for line in fr:
                line = line.strip()
                if line:
                    master_records.extend(_identify_and_return_records(line))
    except FileNotFoundError:
        print(
            "[!] Input file specified by you does not exist. Please check file path and location."
        )
        return []
    except OSError:
        print("[!] Unable to open the file. Please check file path and permissions!")
        return []

    if shuffle:
        random.shuffle(master_records)
    return master_records


def read_input_and_gen_list(inputstr, shuffle=False):
    master_records = _identify_and_return_records(inputstr)
    if shuffle:
        random.shuffle(master_records)
    return master_records
