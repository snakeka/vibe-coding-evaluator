"""benchmark — Cross-Model Benchmarker (Component 3, §4.5, Appendix B.3).

Implements the cross-model comparison layer that issues the §3.5 frozen
prompt set to four providers (per §5.5). The common `generate()`
interface is in ``benchmark.provider_layer``; the parallel dispatcher
is in ``benchmark.dispatcher``; the per-provider output normalisation
is in ``benchmark.normaliser``.
"""
__version__ = "0.1.0"
