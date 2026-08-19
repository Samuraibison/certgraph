def test_clear_removes_edges(graph, chain_certs):
    graph.import_certificates(chain_certs)
    assert graph.report_fingerprint_edges()

    graph.clear()

    assert graph.report_fingerprint_edges() == []


def test_clear_returns_self(graph):
    assert graph.clear() is graph


def test_clear_resets_dn_search(graph, self_signed_cert):
    graph.import_certificates(self_signed_cert)
    dn = self_signed_cert.subject.rfc4514_string()
    assert graph.fingerprint_from_distinguished_name(dn) is not None

    graph.clear()

    assert graph.fingerprint_from_distinguished_name(dn) is None
