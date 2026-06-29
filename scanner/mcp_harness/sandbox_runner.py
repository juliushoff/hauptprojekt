from __future__ import annotations


class SandboxNotImplemented(RuntimeError):
    pass


def run_in_docker(*_args, **_kwargs):
    """Placeholder for the next iteration.

    The current harness validates target parsing, MCP stdio startup, contract
    derivation, test generation, and report output locally. Unknown MCP servers
    should only be run after this module starts each target in a fresh Docker
    container with resource limits and no host secrets.
    """
    raise SandboxNotImplemented("Docker sandbox execution is not implemented yet")
