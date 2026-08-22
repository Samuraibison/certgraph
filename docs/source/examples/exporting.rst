Exporting to DOT
==================

:meth:`~certgraph.certgraph.export_dot` renders the current digraph as a DOT language string,
which can be piped through the ``dot`` command line tool (or an online renderer) to produce an
image:

.. code-block:: python

   with open("path/to/output.dot", "w") as f:
       f.write(graph.export_dot())

.. code-block:: bash

   dot -Tsvg output.dot -o graph.svg

This produces:

.. image:: /_static/basic_example.svg
   :alt: Basic example certificate graph

Each node is labelled with the certificate's RFC4514 distinguished name and validity period.
Certificates that are outside their validity window (see
:meth:`~certgraph.certgraph.certificate_invalid_at`) are highlighted in red.

Legend
------

By default a legend explaining the node colouring is added as a subgraph. Pass ``add_legend=False``
to omit it:

.. code-block:: python

   graph.export_dot(add_legend=False)
