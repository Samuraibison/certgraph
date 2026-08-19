def test_empty_graph_has_no_edges(graph):
    assert graph.report_fingerprint_edges() == []


def test_self_signed_certificate_produces_self_loop(graph, self_signed_cert):
    graph.import_certificates(self_signed_cert)
    edges = graph.report_fingerprint_edges()
    assert len(edges) == 1
    src, _, dst = edges[0].partition(" -> ")
    assert src == dst


def test_chain_produces_expected_number_of_edges(graph, chain_certs):
    graph.import_certificates(chain_certs)
    # one self-loop for the root, plus one edge linking each subsequent cert to its issuer
    assert len(graph.report_fingerprint_edges()) == len(chain_certs)


def test_unrelated_self_signed_certs_do_not_link(graph, make_chain):
    cert_a = make_chain(1, cns=["alpha-root"])[0]
    cert_b = make_chain(1, cns=["beta-root"])[0]
    graph.import_certificates([cert_a, cert_b])

    edges = graph.report_fingerprint_edges()
    assert len(edges) == 2
    for edge in edges:
        src, _, dst = edge.partition(" -> ")
        assert src == dst


def test_edge_report_format_uses_truncated_fingerprints(graph, self_signed_cert):
    graph.import_certificates(self_signed_cert)
    edge = graph.report_fingerprint_edges()[0]
    src, _, dst = edge.partition(" -> ")
    assert len(src) == 8
    assert len(dst) == 8
