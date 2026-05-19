#!/bin/sh
set -e

echo "==> Upgrading Superset DB schema..."
superset db upgrade

echo "==> Initialising Superset (roles, permissions)..."
superset init

echo "==> Creating admin user..."
superset fab create-admin \
  --username admin \
  --firstname Admin \
  --lastname User \
  --email admin@example.com \
  --password admin \
  || echo "Admin user already exists."

echo "==> Superset init complete."
