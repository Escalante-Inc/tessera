#!/bin/bash
set -e

echo "Building..."
swift build

echo "Removing existing code signature..."
codesign --remove-signature .build/debug/tessera || true

echo "Re-signing with entitlements..."
codesign \
  --entitlements Sources/SmartCard.entitlements \
  -s - \
  .build/debug/tessera
