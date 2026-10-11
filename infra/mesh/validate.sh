#!/usr/bin/env bash
# Validación estática de la malla SIN clúster: esquema de los CRD (kubeconform) + análisis semántico de Istio (istioctl analyze)
# + render del IstioOperator + invariantes de seguridad (node --test). Uso: infra/mesh/validate.sh
set -euo pipefail
cd "$(dirname "$0")"
ISTIO=1.24.2; KC=0.6.7; T="${MESH_TOOLS:-${TMPDIR:-/tmp}/mesh-tools}"; mkdir -p "$T"
[ -x "$T/istio-$ISTIO/bin/istioctl" ] || { curl -fsSL "https://github.com/istio/istio/releases/download/$ISTIO/istio-$ISTIO-linux-amd64.tar.gz" | tar xz -C "$T"; }
[ -x "$T/kubeconform" ] || { curl -fsSL "https://github.com/yannh/kubeconform/releases/download/v$KC/kubeconform-linux-amd64.tar.gz" | tar xz -C "$T" kubeconform; }

echo "▶ generated/ al día";                 node generate.mjs --check
echo "▶ invariantes de seguridad";          node --test test/mesh.test.mjs >/dev/null && echo "   ok"
cd generated; FILES=$(ls *.yaml | grep -v '^05-')
echo "▶ esquema (kubeconform --strict)";    "$T/kubeconform" -strict -summary -schema-location default \
  -schema-location 'https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json' $FILES
echo "▶ istioctl analyze";                  "$T/istio-$ISTIO/bin/istioctl" analyze --use-kube=false --failure-threshold Warning -n segundo-cerebro $FILES
echo "▶ IstioOperator → manifiestos";       "$T/istio-$ISTIO/bin/istioctl" manifest generate -f 05-istio-operator.yaml >/dev/null && echo "   ok"
