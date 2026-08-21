def test_export_dot_returns_string(graph):
    assert isinstance(graph.export_dot(), str)


def test_export_dot_empty_graph_has_no_edges(graph):
    dot = graph.export_dot()
    assert "digraph" in dot
    assert "->" not in dot


def test_export_dot_includes_node_labels(graph, self_signed_cert):
    graph.import_certificates(self_signed_cert)
    dn = self_signed_cert.subject.rfc4514_string()

    dot = graph.export_dot()

    assert f"DN: {dn}" in dot


def test_export_dot_includes_validity_period(graph, self_signed_cert):
    graph.import_certificates(self_signed_cert)
    not_before = self_signed_cert.not_valid_before_utc.isoformat()
    not_after = self_signed_cert.not_valid_after_utc.isoformat()

    dot = graph.export_dot()

    # joined with an arrow character rather than '->', to avoid being confused with edge syntax
    assert f"Valid: {not_before} → {not_after}" in dot


def test_export_dot_node_shape_is_box(graph, self_signed_cert):
    graph.import_certificates(self_signed_cert)

    dot = graph.export_dot()

    assert "shape=box" in dot


def test_export_dot_includes_edges(graph, chain_certs):
    graph.import_certificates(chain_certs)

    dot = graph.export_dot()

    # one self-loop for the root, plus one edge per subsequent certificate
    assert dot.count("->") == len(chain_certs)


def test_export_dot_does_not_write_file(graph, self_signed_cert, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    graph.import_certificates(self_signed_cert)

    graph.export_dot()

    assert not (tmp_path / "test_out.dot").exists()
