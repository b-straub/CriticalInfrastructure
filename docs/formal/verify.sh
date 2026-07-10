#!/bin/sh
set -e

echo "Verifying Dashboard Protocol Security Properties..."
tamarin-prover --prove docs/formal/dashboard.spthy

echo "Verifying OTA Delivery Security Properties..."
tamarin-prover --prove docs/formal/ota.spthy

echo "Verification complete!"
