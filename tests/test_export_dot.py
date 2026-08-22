def test_export_dot_returns_string(graph):
    assert isinstance(graph.export_dot(), str)


def test_export_dot_empty_graph_has_no_edges(graph):
    dot = graph.export_dot(add_legend=False)
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


def test_export_dot_highlights_expired_certificate(graph, expired_cert):
    graph.import_certificates(expired_cert)

    dot = graph.export_dot()

    assert "fillcolor=tomato" in dot


def test_export_dot_does_not_highlight_valid_certificate(graph, self_signed_cert):
    graph.import_certificates(self_signed_cert)

    # legend is disabled so its own "tomato" legend node doesn't interfere
    dot = graph.export_dot(add_legend=False)

    assert "fillcolor=white" in dot
    assert "tomato" not in dot


def test_export_dot_includes_edges(graph, chain_certs):
    graph.import_certificates(chain_certs)

    dot = graph.export_dot(add_legend=False)

    # one self-loop for the root, plus one edge per subsequent certificate
    assert dot.count("->") == len(chain_certs)


def test_export_dot_does_not_write_file(graph, self_signed_cert, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    graph.import_certificates(self_signed_cert)

    graph.export_dot()

    assert not (tmp_path / "test_out.dot").exists()


def test_export_dot_includes_legend_by_default(graph):
    dot = graph.export_dot()

    assert "subgraph cluster_legend" in dot
    assert "label=Legend" in dot
    assert 'legend_valid [label=Valid, shape=box, style=filled, fillcolor=white]' in dot
    assert 'legend_invalid [label=Invalid, shape=box, style=filled, fillcolor=tomato]' in dot


def test_export_dot_legend_can_be_disabled(graph):
    dot = graph.export_dot(add_legend=False)

    assert "cluster_legend" not in dot
    assert "legend_valid" not in dot
    assert "legend_invalid" not in dot


def test_export_dot_legend_is_dashed(graph):
    dot = graph.export_dot()

    assert "style=dashed" in dot


def test_export_dot_legend_nodes_are_ranked_top_to_bottom(graph):
    dot = graph.export_dot()

    # invisible edge forces the two legend nodes onto separate ranks
    assert "legend_valid -> legend_invalid [style=invis]" in dot
