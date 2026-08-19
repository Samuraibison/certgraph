from cryptography.hazmat.primitives import hashes


def test_returns_none_for_empty_graph(graph):
    assert graph.fingerprint_from_distinguished_name("CN=whatever") is None


def test_exact_match_returns_correct_fingerprint(graph, chain_certs):
    graph.import_certificates(chain_certs)
    target = chain_certs[1]
    dn = target.subject.rfc4514_string()
    expected_fp = target.fingerprint(hashes.SHA256()).hex()

    result = graph.fingerprint_from_distinguished_name(dn)

    assert result == expected_fp


def test_fuzzy_match_finds_closest_dn(graph, chain_certs):
    graph.import_certificates(chain_certs)
    target = chain_certs[0]
    dn = target.subject.rfc4514_string()
    typo_dn = dn[:-1]  # drop a character to force a fuzzy, non-exact match
    expected_fp = target.fingerprint(hashes.SHA256()).hex()

    result = graph.fingerprint_from_distinguished_name(typo_dn)

    assert result == expected_fp
