"""Sphinx configuration for certgraph documentation."""

import os
import sys
from importlib.metadata import version as get_version

sys.path.insert(0, os.path.abspath("../../src"))

# -- Project information -----------------------------------------------

project = "certgraph"
copyright = "2026, Chris Adshead"
author = "Chris Adshead"
release = get_version("certgraph")
version = ".".join(release.split(".")[:2])

# -- General configuration -----------------------------------------------

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
    "sphinx.ext.intersphinx",
    "sphinx_autodoc_typehints",
]

templates_path = ["_templates"]
exclude_patterns = []

# -- Autodoc / Napoleon ---------------------------------------------------

autodoc_default_options = {
    "members": True,
    "undoc-members": True,
    "show-inheritance": True,
}
autodoc_typehints = "description"
autodoc_member_order = "bysource"

napoleon_google_docstring = True
napoleon_numpy_docstring = False

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "cryptography": ("https://cryptography.io/en/latest/", None),
    "networkx": ("https://networkx.org/documentation/stable/", None),
}

# -- Options for HTML output -----------------------------------------------

html_theme = "sphinx_rtd_theme"
html_static_path = ["_static"]
