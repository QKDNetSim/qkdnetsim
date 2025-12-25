# Contributing to the Quantum Key Distribution Network Simulation Module for NS-3 (QKDNetSim)

Welcome! We're excited that you're interested in contributing to QKDNetSim development. This guide provides instructions how to report issues, suggest features, and contribute new code.

---

## Reporting Bugs / Requesting Features

Use this [**GitHub Issues**](https://github.com/QKDNetSim/qkdnetsim/issues) tab to report bugs or request features.

Please include:
- A descriptive title
- Environment details (OS, NS-3 version, commit hash)
- Steps to reproduce (for bugs)
- Suggested behavior (for features)

---

## Development Setup

### Building the Simulator

This module is designed to work with NS-3 (ns-3.44 or later).

```bash
./ns3 configure --enable-examples --enable-mpi --enable-sudo
./ns3 build
```
Run the quantum examples
```bash
./ns3 run examples_qkd_etsi_014
./ns3 run examples_qkd_etsi_004
./ns3 run examples_secoqc
./ns3 run examples_qkd_etsi_combined_input
./ns3 run examples_qkd_etsi_014_emulation_tap
```

## Submitting Contributions

### Workflow

1. Fork the repo.
2. Make your changes (code, tests, examples, docs).
3. Ensure your code builds and passes all tests.
4. Commit with a descriptive message.
5. Open a Merge Request on GitHub, linking any related issue.

### Commit Message Style

Use clear and conventional commit messages, e.g.:

```
qkd: add support for KMS new feature
docs: update README with simulation instructions
```

## PR Checklist

Before submitting:
- [ ] Code compiles and runs
- [ ] New features have examples or tests
- [ ] Docs updated (README.md, inline Doxygen)
- [ ] Follows NS-3 coding style
- [ ] LICENSE headers included in new files

## Code Style

We follow the [NS-3 coding conventions](https://www.nsnam.org/docs/contributing/html/coding-style.html#coding-style):
- 2-space indentation
- K&R brace style
- Doxygen-style comments
- Use NS_LOG, NS_ASSERT, etc. as per NS-3 guidelines

Run clang-format if applicable to maintain consistency.

## Documentation

- Code should be well-commented with Doxygen
- Update README.md and example descriptions as needed
- Use doc/ for extended usage or design documents
