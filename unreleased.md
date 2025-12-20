### Changed
- **UI/UX**: The "Rotate URL" button is now automatically disabled for services that have "Randomize Suffix" turned off, as static subdomains do not support rotation.
- **Docker**: Cleaned up `entrypoint.sh` startup logs to remove verbose diagnostic information.
