Walking the chain
==================

Certificates are linked in the digraph by subject/issuer, so you can walk up towards a root or
down towards leaves using fingerprints.

Get the issuer of a certificate with :meth:`~certgraph.certgraph.get_issuer_fingerprint`:

.. code-block:: python

   fingerprint = "77c4b5b12b79887b8c709df826cff89a7268071593de5cc84053b8c00302b2fb"
   issuer_fingerprint = graph.get_issuer_fingerprint(fingerprint)
   # "965e8d87f96ccf564726ff5e97ea4d6b18731d9b762ef9510479f628bc85837e"

Get the certificates issued *by* a certificate with
:meth:`~certgraph.certgraph.get_child_fingerprints`:

.. code-block:: python

   child_fingerprints = graph.get_child_fingerprints(fingerprint)
   # ["3cf372288714b52298222bb1f8cf51dce3f1e60147ec53f9ee3dc28e8766c734", ...]

Both raise :exc:`ValueError` if the fingerprint isn't present in the digraph. If a certificate's
issuer was never imported, ``get_issuer_fingerprint`` returns ``None``. A self-signed root is
different: its subject and issuer are the same name, so it forms a self-loop and
``get_issuer_fingerprint`` returns the certificate's *own* fingerprint rather than ``None`` — see
the worked example below.

Worked example: leaf to root
------------------------------

Given a three-certificate chain — ``root-authority`` (self-signed) issuing
``intermediate-ca``, which issues ``leaf-service`` — walk from the leaf up to the root by
repeatedly following ``get_issuer_fingerprint`` until it returns either ``None`` (issuer not
imported) or the current fingerprint again (a self-signed root):

.. code-block:: python

   from certgraph import certgraph as cg

   with open("path/to/chain.pem") as f:
       chain_pem = f.read()  # root-authority -> intermediate-ca -> leaf-service

   graph = cg().import_certificates(chain_pem)

   fingerprint = graph.fingerprint_from_distinguished_name("CN=leaf-service")
   chain = [fingerprint]

   while True:
       issuer_fingerprint = graph.get_issuer_fingerprint(fingerprint)
       if issuer_fingerprint is None or issuer_fingerprint == fingerprint:
           break
       chain.append(issuer_fingerprint)
       fingerprint = issuer_fingerprint

   for fp in chain:
       print(graph.get_certificate(fp).subject.rfc4514_string())
   # CN=leaf-service
   # CN=intermediate-ca
   # CN=root-authority

The loop terminates on ``fingerprint == issuer_fingerprint`` rather than ``issuer_fingerprint is
None`` because the root's self-loop means it is reported as its own issuer.

Checking validity
------------------

:meth:`~certgraph.certgraph.certificate_invalid_at` checks whether a certificate is outside its
validity window — either not yet valid or expired — at a given point in time (UTC now by
default):

.. code-block:: python

   from datetime import datetime, timezone

   graph.certificate_invalid_at(fingerprint)
   graph.certificate_invalid_at(fingerprint, datetime(2020, 1, 1, tzinfo=timezone.utc))
