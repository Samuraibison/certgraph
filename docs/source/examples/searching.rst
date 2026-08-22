Searching and lookup
=====================

Certificates are indexed by *fingerprint* (a SHA256 hash of the certificate's public bytes)
rather than by distinguished name, so lookups are unambiguous even with malformed or
adversarially crafted names. See :ref:`genindex` for the full method list.

Since fingerprints aren't practical to type by hand,
:meth:`~certgraph.certgraph.fingerprint_from_distinguished_name` fuzzy-matches a distinguished
name against the imported certificates and returns the fingerprint of the best match:

.. code-block:: python

   dn = "CN=f3ec133b-4"
   fingerprint = graph.fingerprint_from_distinguished_name(dn)
   print(fingerprint)
   # "77c4b5b12b79887b8c709df826cff89a7268071593de5cc84053b8c00302b2fb"

Once you have a fingerprint, :meth:`~certgraph.certgraph.get_certificate` returns the underlying
:class:`cryptography.x509.Certificate`:

.. code-block:: python

   cert = graph.get_certificate(fingerprint)
   print(cert.subject.rfc4514_string())
   # "CN=f3ec133b-4"
