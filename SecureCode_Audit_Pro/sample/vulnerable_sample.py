
"""Intentionally vulnerable sample for static security analysis."""

import subprocess
import hashlib
import pickle
import io

PASSWORD = "admin123"


def calculate_expression(user_input):
    return eval(user_input)


def display_message(user_input):
    return subprocess.run(
        "echo " + user_input,
        shell=True,
        capture_output=True,
        text=True,
    )


def generate_hash(value):
    return hashlib.md5(value.encode()).hexdigest()


def load_data(data):
    return pickle.load(io.BytesIO(data))
