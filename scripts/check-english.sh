#!/usr/bin/env bash
# Reads text from stdin and fails if it looks like Spanish.
# Heuristic, not a language detector: it flags Spanish-only characters and
# common Spanish words. Proper names go in .github/english-allowlist.txt.
#
# Usage: some-command | scripts/check-english.sh [label]
set -euo pipefail
export LC_ALL=C.UTF-8

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
allowlist="$root/.github/english-allowlist.txt"
label="${1:-input}"

words='de|del|la|las|los|el|que|para|por|con|sin|una|unos|unas|es|est[aá]|esta|este|estos|pero|cuando|como|muy|tambi[eé]n|seg[uú]n|desde|hasta|agrega|agregar|agregado|añade|añadir|arregla|arreglo|arreglar|corrige|corregir|cambio|cambios|cambia|archivo|archivos|prueba|pruebas|nuevo|nueva|elimina|eliminar|actualiza|actualizar|clave|firma|firmar|contraseña|mensaje|se'
# Words must be whitespace-delimited so that "ls -la" or hex like "...:DE" do not match
pattern="[áéíóúñÁÉÍÓÚÑ¿¡]|(^|[[:space:]])($words)([[:space:],.;:!?]|$)"

text="$(cat)"
if [[ -f "$allowlist" ]]; then
    while IFS= read -r allowed; do
        [[ -z "$allowed" || "$allowed" == \#* ]] && continue
        text="${text//"$allowed"/}"
    done < "$allowlist"
fi

if matches="$(grep -n -E "$pattern" <<< "$text")"; then
    echo "error: $label looks like Spanish; everything in this project must be in English:" >&2
    sed 's/^/  /' <<< "$matches" >&2
    exit 1
fi
