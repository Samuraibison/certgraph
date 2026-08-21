from datetime import timedelta

import pytest
from cryptography.hazmat.primitives import hashes


def test_raises_for_unknown_fingerprint(graph):
    with pytest.raises(ValueError):
        graph.certificate_invalid_at("does-not-exist")


def test_certificate_within_validity_period_is_valid(graph, self_signed_cert):
    graph.import_certificates(self_signed_cert)
    fingerprint = self_signed_cert.fingerprint(hashes.SHA256()).hex()

    assert graph.certificate_invalid_at(fingerprint) is False


def test_expired_certificate_is_invalid(graph, expired_cert):
    graph.import_certificates(expired_cert)
    fingerprint = expired_cert.fingerprint(hashes.SHA256()).hex()

    assert graph.certificate_invalid_at(fingerprint) is True


def test_not_yet_valid_certificate_is_invalid(graph, self_signed_cert):
    graph.import_certificates(self_signed_cert)
    fingerprint = self_signed_cert.fingerprint(hashes.SHA256()).hex()
    before_validity = self_signed_cert.not_valid_before_utc - timedelta(days=1)

    assert graph.certificate_invalid_at(fingerprint, at_time=before_validity) is True


def test_at_time_controls_validity_check(graph, self_signed_cert):
    graph.import_certificates(self_signed_cert)
    fingerprint = self_signed_cert.fingerprint(hashes.SHA256()).hex()
    after_validity = self_signed_cert.not_valid_after_utc + timedelta(days=1)

    assert graph.certificate_invalid_at(fingerprint, at_time=after_validity) is True
