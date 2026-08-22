from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from datetime import datetime, timezone
import networkx as nx
import pydot
from rapidfuzz import fuzz


class certgraph:
    """Class for creating and exploring directed graphs of X.509 certificates."""

    def __init__(self) -> None:
        """Initialise an empty certgraph object."""
        self._certlist: set[x509.Certificate] = []
        self._graph = nx.DiGraph()

    def __len__(self) -> int:
        """Get number of certificates imported."""
        return len(self._certlist)

    def import_certificates(
        self,
        certificates: (
            x509.Certificate | str | bytes | list[x509.Certificate | str | bytes]
        ),
    ) -> certgraph:
        """
        Import one or more certificates and regenerate the certificate digraph.

        Args:
            certificates: Certificates to import, either individual or a list. x509.Certificate objects are directly imported, str is assumed to be PEM encoded, bytes are assumed to be DER encoded.

        Returns:
            Returns self to allow method chaining.

        Raises:
            TypeError: Certificate type is not supported (i.e. not x509.Certificate, str or bytes)
        """
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
                pem_certs = x509.load_pem_x509_certificates(cert.encode("utf-8"))
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
        """Generate a networkx digraph from the provided list of certificates."""
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
        """
        Get the list of all edges in the form 'fingerprint1 -> fingerprint2'. Only contains the first 8 characters of each fingerprint, because this is mostly for debugging from a terminal without having to generate a complete graph image.

        Returns:
            List of all edges in the current certificate digraph in terms of fingerprints.
        """
        return [f"{edge[0][:8]} -> {edge[1][:8]}" for edge in self._graph.edges()]

    def _generate_dot_legend(self) -> pydot.Cluster:
        """Generate the optional legend for the dot output."""
        cluster = pydot.Cluster("legend", label="Legend", style="dashed")

        nodes = [
            pydot.Node("legend_valid", label="Valid", shape="box", style="filled", fillcolor="white"),
            pydot.Node("legend_invalid", label="Invalid", shape="box", style="filled", fillcolor="tomato")
        ]

        for i, n in enumerate(nodes):
            cluster.add_node(n)

            # Add invisible edge to force the nodes to appear on different ranks (i.e. top-bottom direction)
            if i != len(nodes) - 1:
                cluster.add_edge(pydot.Edge(nodes[i], nodes[i + 1], style="invis"))

        return cluster

    def export_dot(self, add_legend: bool=True) -> str:
        """
        Export the current certificate digraph in the dot language.

        Args:
            add_legend: Add a legend with the node colours to the graph output. Default is True.

        Returns:
            The certificate digraph rendered as a dot language string.
        """
        dot_graph = nx.DiGraph()

        for fingerprint, data in self._graph.nodes(data=True):
            cert: x509.Certificate = data["certificate"]
            validity_time_str = f"{cert.not_valid_before_utc.isoformat()} → {cert.not_valid_after_utc.isoformat()}"
            invalid = self.certificate_invalid_at(fingerprint)

            label = f"DN: {cert.subject.rfc4514_string()}"
            label += f"\nValid: {validity_time_str}"

            if invalid:
                node_color = "tomato"
            else:
                node_color = "white"

            dot_graph.add_node(
                fingerprint,
                label=label,
                shape="box",
                style="filled",
                fillcolor=node_color,
            )

        dot_graph.add_edges_from(self._graph.edges())
        dot_out = nx.drawing.nx_pydot.to_pydot(dot_graph)

        if add_legend:
            dot_out.add_subgraph(self._generate_dot_legend())

        return dot_out.to_string()

    def clear(self) -> certgraph:
        """
        Remove all certificates imported and clear the digraph.

        Returns:
            Returns self to allow method chaining.
        """
        self._certlist.clear()
        self._graph.clear()
        return self

    def fingerprint_from_distinguished_name(self, dn: str, cutoff: int = 0) -> str:
        """
        Get the fingerprint of the imported certificate with the best fuzzy-search match between the requested distinguised name and the rfc4514 string of each imported certificate.

        Args:
            dn: The distinguished name to use as the basis for the fuzzy-search.
            cutoff: Cutoff value for matching, from 0-100. 0 will always return the closest match (even if poor), 100 will only ever return an exact match.

        Returns:
            The fingerprint of the certificate with the closes matching distinguished name to the one requested. Can also return None if there are no certificates above the cutoff threshold.
        """
        if (cutoff < 0) or (cutoff > 100):
            raise ValueError("cutoff must be between 0-100")

        # Evaluate the nodes
        nodes: list[tuple[str, dict]] = list(self._graph.nodes(data=True))

        # Sort using a fuzzy-search
        ranked = sorted(
            nodes,
            key=lambda t: fuzz.ratio(
                dn, t[1]["certificate"].subject.rfc4514_string(), score_cutoff=cutoff
            ),
        )

        if not ranked:
            return None

        return ranked[-1][0]

    def get_certificate(self, fingerprint: str) -> x509.Certificate | None:
        """
        Get an imported ceritficate based on the fingerprint.

        Args:
            fingerprint: Fingerprint of the certificate to get. Use fingerprint_from_distinguished_name() to resolve the fingerprint from a DN.

        Returns:
            Certificate that matches the provided fingerprint or None if it doesn't exist.
        """
        if fingerprint not in self._graph.nodes:
            return None

        return self._graph.nodes[fingerprint]["certificate"]

    def get_issuer_fingerprint(self, fingerprint: str) -> str:
        """
        Get the fingerprint of the issuer certificate.

        Args:
            fingerprint: Fingerprint of the certificate to get the issuer of.

        Returns:
            The fingerprint of the issuing certificate or None if not present in the digraph.

        Raises:
            ValueError: If certificate with the supplied fingerprint isn't in the digraph.
        """
        if fingerprint not in self._graph.nodes:
            raise ValueError(
                f"Fingerprint supplied doesn't match any imported certificate."
            )

        return next(self._graph.predecessors(fingerprint), None)

    def get_child_fingerprints(self, fingerprint: str) -> str:
        """
        Get the fingerprints of any certificates issued by the certificate with the provided fingerprint.

        Args:
            fingerprint: Fingerprint of the certificate to get the child certificates of.

        Returns:
            The list of fingerprints belonging to child certificates.

        Raises:
            ValueError: If certificate with the supplied fingerprint isn't in the digraph.
        """
        if fingerprint not in self._graph.nodes:
            raise ValueError(
                f"Fingerprint supplied doesn't match any imported certificate."
            )

        return list(self._graph.successors(fingerprint))

    def remove_certificate(self, fingerprint: str) -> None:
        """
        Remove an imported ceritficate based on the fingerprint and update the certificate digraph.

        Args:
            fingerprint: Fingerprint of the certificate to remove. Use fingerprint_from_distinguished_name() to resolve the fingerprint from a DN.
        """
        if fingerprint in self._graph.nodes:
            cert = self._graph.nodes[fingerprint]["certificate"]

            self._graph.remove_node(fingerprint)

            if cert in self._certlist:
                self._certlist.remove(cert)

    def certificate_invalid_at(
        self, fingerprint: str, at_time: datetime | None = None
    ) -> bool:
        """
        Check if an imported certificate is outside its validity period - either not yet valid or expired.

        Args:
            fingerprint: Fingerprint of the certificate to check.
            at_time: When the certificate validity will be checked against. None value defaults to now (UTC).

        Returns:
            True if the certificate is not yet valid or expired at the given time, otherwise false.

        Raises:
            ValueError: If certificate with the supplied fingerprint isn't in the digraph.
        """
        if fingerprint not in self._graph.nodes:
            raise ValueError(
                f"Fingerprint supplied doesn't match any imported certificate."
            )

        if at_time is None:
            at_time = datetime.now(timezone.utc)

        cert = self.get_certificate(fingerprint)
        return at_time < cert.not_valid_before_utc or at_time > cert.not_valid_after_utc
