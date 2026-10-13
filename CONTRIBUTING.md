# Contributing to Lattice

Thanks for helping improve Lattice.

Lattice is currently an early public release focused on safe operation of small trusted Linux fleets. Contributions are welcome, especially reproducible bug reports, regression tests, documentation fixes, clean-install findings, and narrowly scoped reliability improvements.

## Before opening a pull request

1. Open an issue first for larger behavior or architecture changes.
2. Keep each pull request focused on one problem.
3. Add or update tests when the change affects behavior.
4. Do not weaken authentication, host-key verification, privilege boundaries, restore safety, or Daily Care safety checks merely to make an operation easier.
5. Do not commit credentials, tokens, pairing codes, private keys, real home-LAN addresses, usernames, or private fleet state.

## Development setup

Use a normal Git clone:

```bash
git clone https://github.com/dundunna1990/lattice-public.git
cd lattice-public
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
```

Run the normal test suite with:

```bash
pytest
```

Real-machine E2E suites are opt-in and may change system, network, pairing, backup, or fleet state. Read their safety gates before running them.

## Pull requests

A useful pull request should explain:

- the problem
- the root cause
- the exact behavior changed
- how the change was tested
- any remaining limitations

Prefer a regression test that fails before the fix and passes after it.

## Security issues

Please do not publish sensitive exploit details as a normal issue. Read [docs/SECURITY.md](docs/SECURITY.md) first.

## License

By contributing to Lattice, you agree that your contributions will be licensed under the Apache License 2.0.
