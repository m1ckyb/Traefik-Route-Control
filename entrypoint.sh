#!/bin/sh

# Get IDs from environment or use defaults
USER_ID=${PUID:-1000}
GROUP_ID=${PGID:-1000}

# Set timezone if TZ is set
if [ -n "$TZ" ] && [ -f "/usr/share/zoneinfo/$TZ" ]; then
    ln -snf "/usr/share/zoneinfo/$TZ" /etc/localtime
    echo "$TZ" > /etc/timezone
fi

# Safely update the group ID if it doesn't match
if [ "$(getent group appgroup | cut -d: -f3)" != "$GROUP_ID" ]; then
    groupmod -o -g "$GROUP_ID" appgroup
fi

# Safely update the user ID if it doesn't match
if [ "$(id -u appuser)" != "$USER_ID" ]; then
    usermod -o -u "$USER_ID" appuser
fi

# Ensure data directory exists
mkdir -p /app/data

# Apply ownership and FORCE permissions
# Since this is likely a WSL2/Windows mount, standard chown might be ignored
# so we use chmod 777 to guarantee access for the appuser
chown -R appuser:appgroup /app > /dev/null 2>&1
chown -R appuser:appgroup /app/data > /dev/null 2>&1
chmod -R 777 /app/data > /dev/null 2>&1

# Run the application
echo "[$(date '+%Y-%m-%d %H:%M:%S %z')] 👻 RouteGhost: Starting application..."
exec su-exec appuser:appgroup gunicorn --bind 0.0.0.0:5000 main:app
