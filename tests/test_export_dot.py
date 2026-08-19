import pytest

# export_dot()'s actual output generation is still rough and not covered here.
# Only the argument validation, which happens before anything is written, is tested.


def test_export_dot_rejects_invalid_format(graph):
    with pytest.raises(ValueError):
        graph.export_dot(format="jpeg")
