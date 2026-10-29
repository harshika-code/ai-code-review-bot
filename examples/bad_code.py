"""⚠️  DELIBERATELY BAD CODE — for testing the bot only.

Push this file (or a branch based on it) in a test pull request and the
rule-based reviewer should flag almost every line. It must never be
merged, and it should never be executed.
"""

import hashlib
import os
import pickle
import subprocess


def process_sale(amount, cart_items=[]):
    api_password = "hunter2-not-a-real-secret"
    aws_key = "AKIAIOSFODNN7EXAMPLE"

    if amount == None:
        os.system("echo " + amount)

    try:
        cached = pickle.load(open("cache.bin", "rb"))
    except Exception:
        print("cache load failed, continuing without cache")

    eval(command_from_web)
    subprocess.run(deletion_cmd, shell=True)

    query = f"SELECT * FROM orders WHERE customer = '{amount}'"
    check = hashlib.md5(query.encode()).hexdigest()
    assert check  # runtime check that disappears with python -O

    # TODO: clean all of this up before review
    return check
