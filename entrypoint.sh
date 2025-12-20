#!/bin/sh

# Get IDs from environment or use defaults
USER_ID=${PUID:-1000}
GROUP_ID=${PGID:-1000}

echo "👻 RouteGhost: Initialization..."
echo "   - Target UID: $USER_ID"
echo "   - Target GID: $GROUP_ID"

# Safely update the group ID if it doesn't match
if [ "$(getent group appgroup | cut -d: -f3)" != "$GROUP_ID" ]; then
    echo "   - Updating appgroup GID..."
    groupmod -o -g "$GROUP_ID" appgroup
fi

# Safely update the user ID if it doesn't match
if [ "$(id -u appuser)" != "$USER_ID" ]; then
    echo "   - Updating appuser UID..."
    usermod -o -u "$USER_ID" appuser
fi

# Ensure data directory exists
mkdir -p /app/data

# Apply ownership and FORCE permissions
# Since this is likely a WSL2/Windows mount, standard chown might be ignored
# so we use chmod 777 to guarantee access for the appuser
echo "   - Applying ownership (chown -R appuser:appgroup) to /app and /app/data..."
chown -R appuser:appgroup /app
chown -R appuser:appgroup /app/data

echo "   - Applying global permissions (chmod -R 777) to /app/data to override mount restrictions..."
chmod -R 777 /app/data

# Diagnostic: Show current state
echo "   - Filesystem Check (/app/data):"
ls -la /app/data

echo "   - Current Identity:"
id appuser

# Write test as appuser
echo "   - Permission Test:"
su-exec appuser:appgroup touch /app/data/.write_test && echo "     ✅ Write test to /app/data: SUCCESS" || echo "     ❌ Write test to /app/data: FAILED"
rm -f /app/data/.write_test

# Run the application
echo "👻 RouteGhost: Starting application via gunicorn..."
exec su-exec appuser:appgroup gunicorn --bind 0.0.0.0:5000 main:app