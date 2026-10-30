from __future__ import annotations

import csv
import io
import re

import pytest

from sahakari_guard.privacy import Policy, Tokenizer, find_pii, infer_policy, mask_csv_text, mask_text, mask_value
from sahakari_guard.privacy.checksums import luhn_check_digit, luhn_valid, verhoeff_check_digit, verhoeff_valid


def test_verhoeff_round_trip():
    for body in ("23456789012", "99999999999", "50000000001"):
        number = body + verhoeff_check_digit(body)
        assert verhoeff_valid(number)
        wrong = number[:-1] + str((int(number[-1]) + 1) % 10)
        assert not verhoeff_valid(wrong)


def test_luhn_known_values():
    assert luhn_valid("4111111111111111")
    assert not luhn_valid("4111111111111112")
    assert luhn_check_digit("608001123456789") == "6"
    assert not luhn_valid("12ab")


@pytest.mark.parametrize(
    "text, expected, kind",
    [
        ("Aadhaar 2345 6789 0124", "XXXX-XXXX-0124", "aadhaar"),
        ("aadhar no 1234 5678 9012", "XXXX-XXXX-9012", "aadhaar"),
        ("PAN ABCPE1234F", "XXXXXX234F", "pan"),
        ("mob +91 98765 43210", "XXXXXX3210", "mobile"),
        ("call 9876543210 now", "XXXXXX3210", "mobile"),
        ("card 4111 1111 1111 1111", "XXXX-XXXX-XXXX-1111", "card"),
        ("a/c no: 001010001234567", "XXXXXXXXXXX4567", "account"),
        ("mail selvi.k@example.com", "s***@example.com", "email"),
        ("paid kavitha.raman@oksbi", "k***@oksbi", "vpa"),
        ("खाता 001010001234567", "XXXXXXXXXXX4567", "account"),
    ],
)
def test_mask_text_detects_identifiers(text, expected, kind):
    result = mask_text(text)
    assert expected in result.text
    assert result.counts[kind] == 1


def test_reference_numbers_and_amounts_are_kept():
    text = "UPI/630511004211/Rent RRN 630511004219 amount 125000.50 on 2026-11-01"
    result = mask_text(text)
    assert "630511004211" in result.text
    assert "630511004219" in result.text
    assert "125000.50" in result.text
    assert result.total == 0


def test_masking_is_idempotent():
    once = mask_text("Aadhaar 2345 6789 0124 PAN ABCPE1234F 9876543210").text
    twice = mask_text(once)
    assert twice.text == once
    assert twice.total == 0


def test_infer_policy():
    assert infer_policy("account_no") is Policy.LAST4
    assert infer_policy("card_no") is Policy.CARD
    assert infer_policy("aadhaar_number") is Policy.AADHAAR
    assert infer_policy("pan") is Policy.PAN
    assert infer_policy("company") is Policy.TEXT  # contains "pan" but is not a PAN column
    assert infer_policy("customer_name") is Policy.NAME
    assert infer_policy("rrn") is Policy.KEEP
    assert infer_policy("narration") is Policy.TEXT
    assert infer_policy("contact_email") is Policy.EMAIL


def test_pan_column_with_card_number_is_masked_as_card():
    masked, counts = mask_value("4111111111111111", Policy.PAN)
    assert masked == "XXXX-XXXX-XXXX-1111"
    assert counts["card"] == 1


def test_mask_csv_adds_tokens_and_leaves_no_identifiers():
    content = (
        "rrn,account_no,card_no,customer_name,narration,amount\n"
        "630511004211,001010001234567,4111111111111111,Kavitha Raman,KYC Aadhaar 2345 6789 0124 mob 9876543210,1500.00\n"
        "630511004212,001010001234567,4111111111111111,Kavitha Raman,UPI/630511004212/Rent,200.00\n"
    )
    masked, report = mask_csv_text(content, tokenizer=Tokenizer("test-secret"))
    rows = list(csv.DictReader(io.StringIO(masked)))
    assert rows[0]["rrn"] == "630511004211"
    assert rows[0]["account_no"] == "XXXXXXXXXXX4567"
    assert rows[0]["customer_name"] == "K*** R***"
    assert rows[0]["account_no_token"] == rows[1]["account_no_token"] != ""
    assert report.residual == {}
    for raw in ("001010001234567", "4111111111111111", "2345 6789 0124", "9876543210", "Kavitha"):
        assert raw not in masked
    assert report.rows == 2


def test_tokenizer_is_keyed():
    a, b = Tokenizer("one"), Tokenizer("two")
    assert a.token("001") == a.token("001")
    assert a.token("001") != b.token("001")
    assert re.fullmatch(r"tok_[0-9a-f]{12}", a.token("001"))
    with pytest.raises(ValueError):
        Tokenizer("")


def test_find_pii_counts():
    assert find_pii("nothing here 12345") == {}
    assert find_pii("PAN ABCPE1234F")["pan"] == 1
