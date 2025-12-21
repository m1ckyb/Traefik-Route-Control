### Added
- **UI/UX**: Added a "Clear Traefik Routes from Redis" button in the Redis settings to allow manual cleanup of orphan Traefik entries.
- **API**: Added `/api/test/redis/clear` endpoint to facilitate manual Redis cleanup.

### Changed
- **UI/UX**: The "Rotate URL" button is now automatically disabled for services that have "Randomize Suffix" turned off, as static subdomains do not support rotation.
- **Documentation**: Refined the release process instructions in `GEMINI.md` to prevent changelog duplication and clarify the branch merge workflow.
- **Documentation**: Updated `GEMINI.md` with modern development guidelines including non-root execution, named volume usage, and mandatory security/vulnerability testing for new code changes.

### Fixed
- **Core**: Fixed a `SyntaxError` in `main.py` caused by accidentally inserted JavaScript code into the Python backend.
- **Docker**: Cleaned up `entrypoint.sh` startup logs to remove verbose diagnostic information.