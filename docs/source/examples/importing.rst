Importing certificates
=======================

:meth:`~certgraph.certgraph.import_certificates` accepts a single certificate or a list, and
each item may be a PEM string, DER bytes, or an already-parsed
:class:`cryptography.x509.Certificate`. It returns ``self``, so imports can be chained.

Import a single PEM-encoded certificate:

.. code-block:: python

   from certgraph import certgraph as cg

   with open("path/to/cert.pem") as f:
       pem_data = f.read()

   graph = cg().import_certificates(pem_data)
   print(len(graph))
   # 1

A PEM file may also contain a whole PKI (multiple concatenated certificates); these are all
imported and linked by subject/issuer.

Import a mixed PEM/DER dataset, including a PEM containing a whole PKI, using method chaining:

.. code-block:: python

   with open("path/to/cert.pem") as f:
       pem_data = f.read() # 1 cert
   with open("path/to/pki.pem") as f:
       pki_data = f.read() # 3 certs
   with open("path/to/cert.der", "rb") as f:
       der_data = f.read() #1 cert

   graph = (
       cg()
       .import_certificates(pem_data)
       .import_certificates(pki_data)
       .import_certificates(der_data)
   )
   print(len(graph))
   # 5
