"""report — Report Generator (Component 4, §4.5, Appendix B.5).

Produces the per-sample verdict matrix (CSV + JSON), SHA-256
manifest, and stakeholder dashboard consumed by Chapter 6.

Public entry points:
    report.verdict_merger.build_verdict_matrix(...)
    report.divergence_router.route_incomplete_rows(matrix)
    report.exporter.export_csv(matrix, path)
    report.exporter.export_json(matrix, path)
    report.exporter.render_dashboard(matrix, path)
"""
__version__ = "0.1.0"
