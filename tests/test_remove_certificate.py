from cryptography.hazmat.primitives import hashes


def test_removes_node_from_graph(graph, self_signed_cert):
    graph.import_certificates(self_signed_cert)
    fingerprint = self_signed_cert.fingerprint(hashes.SHA256()).hex()

    graph.remove_certificate(fingerprint)

    assert graph.get_certificate(fingerprint) is None


def test_removes_certificate_from_certlist(graph, self_signed_cert):
    graph.import_certificates(self_signed_cert)

    fingerprint = self_signed_cert.fingerprint(hashes.SHA256()).hex()
    graph.remove_certificate(fingerprint)

    assert self_signed_cert not in graph._certlist


def test_unknown_fingerprint_is_a_no_op(graph, chain_certs):
    graph.import_certificates(chain_certs)
    edges_before = graph.report_fingerprint_edges()

    graph.remove_certificate("does-not-exist")

    assert graph.report_fingerprint_edges() == edges_before


def test_removing_intermediate_drops_its_edges(graph, chain_certs):
    graph.import_certificates(chain_certs)
    intermediate_fp = chain_certs[1].fingerprint(hashes.SHA256()).hex()
    leaf_fp = chain_certs[2].fingerprint(hashes.SHA256()).hex()

    graph.remove_certificate(intermediate_fp)

    remaining = graph.report_fingerprint_edges()
    assert all(intermediate_fp[:8] not in edge for edge in remaining)
    # the leaf certificate is still present, just orphaned
    assert graph.get_certificate(leaf_fp) == chain_certs[2]
