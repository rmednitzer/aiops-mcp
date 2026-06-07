{{- define "praxis.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "praxis.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "praxis.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "praxis.labels" -}}
app.kubernetes.io/name: {{ include "praxis.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: praxis
{{- end -}}

{{- define "praxis.selectorLabels" -}}
app.kubernetes.io/name: {{ include "praxis.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "praxis.serviceAccountName" -}}
{{ include "praxis.fullname" . }}
{{- end -}}

{{- define "praxis.image" -}}
{{- $digest := required "image.digest must be set (digest-pinned, ADR-0001)" .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository $digest -}}
{{- end -}}
