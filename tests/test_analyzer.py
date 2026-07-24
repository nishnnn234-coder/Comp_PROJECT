import pytest
from src.services.analyzer import calculate_entropy, derive_verdict

def test_calculate_entropy_empty():
    assert calculate_entropy(b"") == 0.0

def test_calculate_entropy_repetitive():
    # Repetitive byte sequence should have 0 entropy
    data = b"AAAAAAAAAAAAAAA"
    assert calculate_entropy(data) == 0.0

def test_calculate_entropy_high():
    # Random-like sequence of all byte values
    data = bytes(range(256))
    assert calculate_entropy(data) > 7.5

def test_derive_verdict_executable():
    assert derive_verdict("sample.exe", 4.5, 6.8) == "High Risk"

def test_derive_verdict_clean():
    assert derive_verdict("document.pdf", 3.2, 6.8) == "Verified Clean"
