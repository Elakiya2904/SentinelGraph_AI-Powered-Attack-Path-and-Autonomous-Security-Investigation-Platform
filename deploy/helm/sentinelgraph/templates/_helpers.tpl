{{- define "sentinelgraph.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "sentinelgraph.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name (include "sentinelgraph.name" .) | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{- define "sentinelgraph.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "sentinelgraph.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "sentinelgraph.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sentinelgraph.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
