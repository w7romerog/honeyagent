#!/usr/bin/env bash
# Empaqueta agent/ + dependencias para el ZIP de Lambda.
#
# Uso:
#   ./scripts/build_lambda_package.sh
#   cd infra && terraform apply

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
OUTPUT_ZIP="${ROOT_DIR}/infra/lambda_package.zip"

echo "Limpiando build anterior..."
rm -rf "${BUILD_DIR}" "${OUTPUT_ZIP}"
mkdir -p "${BUILD_DIR}"

echo "Instalando dependencias..."
pip install --platform manylinux2014_x86_64 --target "${BUILD_DIR}" \
    --implementation cp --python-version 3.12 --only-binary=:all: \
    -r "${ROOT_DIR}/requirements.txt"

echo "Copiando código del agente..."
cp -r "${ROOT_DIR}/agent" "${BUILD_DIR}/agent"

echo "Empaquetando ${OUTPUT_ZIP}..."
# zipfile de Python en vez del binario zip (no siempre disponible en Windows).
if command -v cygpath >/dev/null 2>&1; then
    BUILD_DIR_FOR_PY="$(cygpath -w "${BUILD_DIR}")"
    OUTPUT_ZIP_FOR_PY="$(cygpath -w "${OUTPUT_ZIP}")"
else
    BUILD_DIR_FOR_PY="${BUILD_DIR}"
    OUTPUT_ZIP_FOR_PY="${OUTPUT_ZIP}"
fi

python -c "
import os
import zipfile

build_dir = r'${BUILD_DIR_FOR_PY}'
output_zip = r'${OUTPUT_ZIP_FOR_PY}'
skip_suffixes = ('.dist-info',)

with zipfile.ZipFile(output_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
    for root, dirs, files in os.walk(build_dir):
        dirs[:] = [d for d in dirs if d != '__pycache__' and not d.endswith(skip_suffixes)]
        for name in files:
            path = os.path.join(root, name)
            arcname = os.path.relpath(path, build_dir)
            zf.write(path, arcname)
"

echo "Listo: ${OUTPUT_ZIP}"
