# Repository Guidelines

## Project Structure & Module Organization

- `lib/claude_protect/` contains Python network isolation, proxy, diagnostics, restoration, and GUI modules.
- `bin/` provides executable CLI entry points; `scripts/` contains installation, packaging, GUI launch, and acceptance tools.
- `extension/` contains the CommonJS VS Code extension and status presentation logic.
- `tests/` contains Python unit tests, JavaScript status tests, and optional Qt smoke tests.
- `docs/` holds architecture, deployment, and verification guides. Edit documentation here and in the root `README.md`; the build copies them into `extension/`.
- `dist/` contains generated VSIX packages, source archives, and checksums.

## Build, Test, and Development Commands

Run from the repository root:

```bash
PYTHONPATH=lib python3 -m unittest discover -s tests -p 'test_*.py' -v
node --test tests/status.test.js
npm --prefix extension run check
python3 scripts/build.py --vsce /path/to/vsce
```

These run Python tests, JavaScript tests, extension syntax checking, and release packaging. Packaging requires an installed Microsoft `@vscode/vsce`; CI uses Node.js 22.

For GUI development, install `requirements-gui.txt` in a virtual environment, then run `python3 scripts/gui.py --demo`. Run Qt checks with `QT_QPA_PLATFORM=offscreen python3 tests/gui_smoke.py`.

## Coding Style & Naming Conventions

Follow existing styles: four-space Python indentation, `snake_case` functions/modules, `PascalCase` classes, and `UPPER_SNAKE_CASE` constants. JavaScript uses two-space indentation, CommonJS, single quotes, and semicolons. Keep the core Python and extension runtime dependency-free; PySide6 belongs to the optional GUI. No formatter or linter is configured.

## Testing Guidelines

Use Python `unittest` and `unittest.mock`, with `tests/test_*.py` files and descriptive `test_*` methods. JavaScript uses `node:test` and strict assertions. No numeric coverage threshold is configured; cover changed behavior, especially rejection paths and failed isolation checks.

Run privileged Linux acceptance scripts only on a recoverable Ubuntu test machine or CI runner without an existing deployment; they install and remove system components. Follow `docs/DEPLOY.md` and distinguish unit results from desktop integration evidence.

## Commit & Pull Request Guidelines

This checkout has no Git metadata, so historical commit conventions cannot be verified. Use concise imperative subjects, such as `Fix relay shutdown handling`. PRs should explain behavior changes, link relevant issues, record validation and platform limitations, and include screenshots for GUI changes.

## Security & Configuration

Read `docs/THREAT_MODEL.md` before changing isolation boundaries. Preserve fail-closed networking, TLS verification, and credential redaction. Keep real proxy credentials, account tokens, and raw sensitive logs out of fixtures and reports.
