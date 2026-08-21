import pytest
from cryptography.hazmat.primitives import hashes


def test_raises_for_unknown_fingerprint(graph):
    with pytest.raises(ValueError):
        graph.get_child_fingerprints("does-not-exist")


def test_leaf_certificate_has_no_children(graph, chain_certs):
    graph.import_certificates(chain_certs)
    leaf_fp = chain_certs[2].fingerprint(hashes.SHA256()).hex()

    assert graph.get_child_fingerprints(leaf_fp) == []


def test_self_signed_certificate_is_its_own_child(graph, self_signed_cert):
    graph.import_certificates(self_signed_cert)
    fingerprint = self_signed_cert.fingerprint(hashes.SHA256()).hex()

    assert graph.get_child_fingerprints(fingerprint) == [fingerprint]


def test_root_returns_itself_and_issued_certificate(graph, chain_certs):
    graph.import_certificates(chain_certs)
    root_fp = chain_certs[0].fingerprint(hashes.SHA256()).hex()
    intermediate_fp = chain_certs[1].fingerprint(hashes.SHA256()).hex()

    # root has a self-loop plus the certificate it issued
    assert set(graph.get_child_fingerprints(root_fp)) == {root_fp, intermediate_fp}


def test_intermediate_returns_only_leaf_it_issued(graph, chain_certs):
    graph.import_certificates(chain_certs)
    intermediate_fp = chain_certs[1].fingerprint(hashes.SHA256()).hex()
    leaf_fp = chain_certs[2].fingerprint(hashes.SHA256()).hex()

    assert graph.get_child_fingerprints(intermediate_fp) == [leaf_fp]
