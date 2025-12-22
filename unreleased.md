### Added

### Changed
- Refactored `main.py` to remove legacy CLI code and `argparse` dependency.
- Hardened `static/js/main.js` against XSS by sanitizing inputs in `showDiagnosticsModal`.

### Fixed

### Removed
- Removed legacy `cmd_on` and `cmd_off` functions from `main.py`.