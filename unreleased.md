### Added
- **MQTT Integration**: Implemented MQTT support for Home Assistant Auto Discovery and control (`paho-mqtt`).
- **Settings UI**: Added MQTT configuration section to the "Integrations" tab with a Test Connection button.
- **Backend**: Added background MQTT handler for state updates and command processing.

### Changed
- **Dependencies**: Added `paho-mqtt` to `requirements.txt`.
- **UI**: Added visual separation (`<hr>`) between MQTT and Redis settings in the Integrations tab.

### Fixed
- **Settings Form**: Resolved issue where "Save Settings" button was unresponsive due to a nested `<form>` tag in the API Keys section. Converted API Key creation to use AJAX/Fetch.
- **Settings Form**: Removed `required` attribute from hidden inputs in the settings form to prevent browser validation blocking submission when tabs are switched.

### Removed