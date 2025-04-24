#!/usr/bin/env bash
set -euo pipefail

cd ../preview
tailwindcss -i ./wwwroot/css/app.css -o ./wwwroot/css/tailwind.css --watch
