#!/bin/bash

YT_DLP_VERSION="$1"
FLASK_APP="$2"

if [ ! -x "$(command -v curl)" ]; then
  echo "Error: curl is not installed" >&2
  exit 1
fi

if [ ! -x "$(command -v unzip)" ]; then
  echo "Error: unzip is not installed" >&2
  exit 1
fi

if [ ! -x "$(command -v python)" ]; then
  echo "Error: python is not installed" >&2
  exit 1
fi

YT_DLP_FILENAME="yt-dlp-${YT_DLP_VERSION}.tar.gz"
YT_DLP_URL="https://github.com/yt-dlp/yt-dlp/releases/download/v${YT_DLP_VERSION}/${YT_DLP_FILENAME}"
YT_DLP_DIR="${HOME}/.local/bin"

mkdir -p "${YT_DLP_DIR}"
curl -sSL "${YT_DLP_URL}" | tar xz -C "${YT_DLP_DIR}" --strip-components=1
ln -s "${YT_DLP_DIR}/yt-dlp" "${HOME}/.local/bin/yt-dlp"

if [ ! -x "$(command -v flask)" ]; then
  echo "Error: flask is not installed" >&2
  exit 1
fi

export FLASK_APP="${FLASK_APP}"
flask run --port=80