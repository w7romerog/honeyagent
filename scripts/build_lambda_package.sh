#!/usr/bin/env bash
# scripts/build_lambda_package.sh
#
# Empaquetado simple de la Lambda (no es un pipeline de CI/CD, es un script de
# build local). Instala las dependencias de pip -incluido el SDK de Anthropic,
# que el runtime de Lambda no trae por defecto- junto al código de agent/ y
# arma el ZIP que infra/lambda.tf sube a AWS Lambda.
#
# Uso:
#   ./scripts/build_lambda_package.sh
#   cd infra && terraform apply ...

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
OUTPUT_ZIP="${ROOT_DIR}/infra/lambda_package.zip"

echo "Limpiando build anterior..."
rm -rf "${BUILD_DIR}" "${OUTPUT_ZIP}"
mkdir -p "${BUILD_DIR}"

echo "Instalando dependencias (incluye el SDK de Anthropic)..."
pip install --platform manylinux2014_x86_64 --target "${BUILD_DIR}" \
    --implementation cp --python-version 3.12 --only-binary=:all: \
    -r "${ROOT_DIR}/requirements.txt"

echo "Copiando código del agente..."
cp -r "${ROOT_DIR}/agent" "${BUILD_DIR}/agent"

echo "Empaquetando ${OUTPUT_ZIP}..."
# Se arma el ZIP con el módulo zipfile de Python (portable) en vez del binario
# `zip`, que no está disponible por defecto en Git Bash para Windows.
# Si estamos en Git Bash sobre Windows, el intérprete de Python es nativo de
# Windows: hay que convertir los paths POSIX (/c/...) a formato Windows con
# cygpath antes de pasárselos.
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
