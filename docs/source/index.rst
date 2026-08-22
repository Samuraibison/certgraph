certgraph
=========

Python package for creating, exploring and displaying directed graphs of X.509 certificates.

Build a directed graph by importing PEM/DER/``x509.Certificate`` objects using subject/issuer
relationships. Explore the generated digraph with the built-in functions and then export the
graph rendered in the DOT language.

Installation
------------

.. code-block:: bash

   pip install certgraph

For development dependencies:

.. code-block:: bash

   pip install certgraph[dev]

Quickstart
----------

.. code-block:: python

   from certgraph import certgraph as cg

   # Open a certificate from a file.
   with open("path/to/cert.pem") as f:
       pem_data = f.read()

   # Import the certificate into a new certgraph object.
   graph = cg().import_certificates(pem_data)

   # Write the DOT language output to a file.   
   with open("path/to/out.dot", "w") as f:
      f.write(graph.export_dot())

Rendering the DOT language as an SVG (with `dot` command line or online tool) produces an output like this:

.. image:: /_static/basic_example.svg
   :alt: Basic example certificate graph

See :doc:`examples/index` for more, and the :doc:`api` reference for the full set of available
methods.

.. toctree::
   :maxdepth: 2
   :hidden:

   examples/index
   api

Indices and tables
-------------------

* :ref:`genindex`
* :ref:`modindex`
