from cryptography import x509
from cryptography.hazmat.primitives import hashes
import networkx as nx


class certgraph:
    def __init__(self) -> None:
        self._certlist: set[x509.Certificate] = []
        self._graph = nx.DiGraph()

    def import_certificates(
        self,
        certificates: (
            x509.Certificate | str | bytes | list[x509.Certificate | str | bytes]
        ),
        pem_encoding: str = "utf-8",
    ) -> certgraph:
        new_certs: set[x509.Certificate] = []

        # If there's only a non-list object being handing in, turn it into an array to keep the same iteration code
        for i, cert in enumerate(
            certificates if isinstance(certificates, list) else [certificates]
        ):
            if isinstance(cert, x509.Certificate):
                # No conversion neccessary
                new_certs.append(cert)
            elif isinstance(cert, str):
                # PEM encoded
                pem_certs = x509.load_pem_x509_certificates(cert.encode(pem_encoding))
                new_certs.extend(pem_certs)
            elif isinstance(cert, bytes):
                # DER encoded
                der_cert = x509.load_der_x509_certificate(cert)
                new_certs.append(der_cert)
            else:
                raise TypeError(
                    f"Cannot import certificate {i} from data type {type(cert)}"
                )

        self._certlist.extend(new_certs)
        self._graph = self._generate_graph(self._certlist)

        return self

    def _generate_graph(self, certificates: set[x509.Certificate]) -> nx.DiGraph:
        G = nx.DiGraph()

        # Pass 1: add nodes and build a subject_dn -> fingerprint index
        subject_index: dict[str, list[str]] = {}
        for cert in certificates:
            fingerprint = cert.fingerprint(hashes.SHA256()).hex()
            G.add_node(fingerprint, certificate=cert)

            subject_dn = cert.subject.rfc4514_string()
            subject_index.setdefault(subject_dn, []).append(fingerprint)

        # Pass 2: add edges using the index
        for fingerprint, data in G.nodes(data=True):
            issuer_dn = data["certificate"].issuer.rfc4514_string()

            for issuer_fingerprint in subject_index.get(issuer_dn, []):
                G.add_edge(issuer_fingerprint, fingerprint)

        return G

    def report_fingerprint_edges(self) -> list[str]:
        return [f"{edge[0][:8]} -> {edge[1][:8]}" for edge in self._graph.edges()]

    def export_dot(self, format: str = "svg") -> str:
        allowed_types = ["svg", "png"]

        if format not in allowed_types:
            raise ValueError(
                f"Cannot export dot graph of type {format} - must be one of {allowed_types}"
            )

        dot_graph = nx.DiGraph()

        for fingerprint, data in self._graph.nodes(data=True):
            label = data["certificate"].subject.rfc4514_string()
            dot_graph.add_node(fingerprint, label=label)
        dot_graph.add_edges_from(self._graph.edges())

        nx.drawing.nx_pydot.write_dot(dot_graph, "./test_out.dot")

        return "dot"

    def clear(self) -> certgraph:
        self._certlist.clear()
        self._graph.clear()
        return self
