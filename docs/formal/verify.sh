#!/bin/sh
set -e

echo "Verifying Dashboard Protocol Security Properties..."
tamarin-prover --prove docs/formal/dashboard.spthy

echo "Verification complete!"
