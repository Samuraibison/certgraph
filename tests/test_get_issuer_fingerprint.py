import pytest
from cryptography.hazmat.primitives import hashes


def test_raises_for_unknown_fingerprint(graph):
    with pytest.raises(ValueError):
        graph.get_issuer_fingerprint("does-not-exist")


def test_self_signed_certificate_is_its_own_issuer(graph, self_signed_cert):
    graph.import_certificates(self_signed_cert)
    fingerprint = self_signed_cert.fingerprint(hashes.SHA256()).hex()

    assert graph.get_issuer_fingerprint(fingerprint) == fingerprint


def test_leaf_returns_direct_issuer_fingerprint(graph, chain_certs):
    graph.import_certificates(chain_certs)
    root_fp = chain_certs[0].fingerprint(hashes.SHA256()).hex()
    intermediate_fp = chain_certs[1].fingerprint(hashes.SHA256()).hex()
    leaf_fp = chain_certs[2].fingerprint(hashes.SHA256()).hex()

    assert graph.get_issuer_fingerprint(intermediate_fp) == root_fp
    assert graph.get_issuer_fingerprint(leaf_fp) == intermediate_fp


def test_unrelated_self_signed_certs_do_not_share_issuer(graph, make_chain):
    cert_a = make_chain(1, cns=["alpha-root"])[0]
    cert_b = make_chain(1, cns=["beta-root"])[0]
    graph.import_certificates([cert_a, cert_b])
    fp_a = cert_a.fingerprint(hashes.SHA256()).hex()
    fp_b = cert_b.fingerprint(hashes.SHA256()).hex()

    assert graph.get_issuer_fingerprint(fp_a) == fp_a
    assert graph.get_issuer_fingerprint(fp_b) == fp_b
