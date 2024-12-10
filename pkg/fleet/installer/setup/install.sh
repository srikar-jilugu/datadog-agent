#!/bin/bash
# Installer for Datadog (www.datadoghq.com).
# Copyright 2016-present Datadog, Inc.
#
set -e

if [ "$(uname -s)" != "Linux" ] || { [ "$(uname -m)" != "x86_64" ] && [ "$(uname -m)" != "aarch64" ]; }; then
  echo "This installer only supports linux running on amd64 or arm64." >&2
  exit 1
fi

tmp_dir="/opt/datadog-packages/tmp"
extracted_base64="${tmp_dir}/download-installer_base64"
downloader_path="${tmp_dir}/download-installer"
script_file="$0"

# 0s are placeholders for the actual start offsets, avoiding to change script lengths
start_amd=$((10#000000000000))
start_arm=$((10#000000000000))

if [ "$UID" == "0" ]; then
  sudo_cmd=''
else
  sudo_cmd='sudo'
fi

install() {
  $sudo_cmd mkdir -p "${tmp_dir}"
  case "$(uname -m)" in
  x86_64)
    write_installer $((start_amd)) $((start_arm-start_amd))
    ;;
  aarch64)
    write_installer $((start_arm)) "0"
    ;;
  esac
  $sudo_cmd chmod +x "${downloader_path}"
  echo "Starting the Datadog installer..."
  $sudo_cmd "${downloader_path}" "$@"
}

write_installer() {
  local skip=$1
  local count=$2
  if [ "$count" -eq "0" ]; then
      dd if="${script_file}" bs=1 skip=$((skip)) status=none of="${extracted_base64}"
  else
      dd if="${script_file}" bs=1 skip=$((skip)) count=$((count)) status=none of="${extracted_base64}"
  fi
  base64 -d "${extracted_base64}" > "${downloader_path}"
}

install "$@"
exit 0

# Embedded binaries used to install Datadog.
# Source: https://github.com/DataDog/datadog-agent/tree/INSTALLER_COMMIT/pkg/fleet/installer
# DO NOT EDIT THIS SECTION MANUALLY.
