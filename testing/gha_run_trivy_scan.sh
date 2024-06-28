set -Eexo pipefail

# input parameters
IMAGE_NAME=${1}

# constants
TRIVY_VERSION=0.52.2
REPORT_FOLDER=$(pwd)/report
REPORT_FILE=trivy-report.md
REPORT_TEMPLATE=trivy-markdown.tpl

echo "[INFO] writing out the report template"
mkdir -p "${REPORT_FOLDER}"
cat <<'EOF' > "${REPORT_FOLDER}/${REPORT_TEMPLATE}"
## Vulnerability Report from [Trivy](https://trivy.dev)

<details>
  {{- if . }}
    {{- range . }}
      {{- if or (gt (len .Vulnerabilities) 0) (gt (len .Misconfigurations) 0) }}
        <h3>Target: <code>{{- if and (eq .Class "os-pkgs") .Type }}{{ .Type | toString | escapeXML }} ({{ .Class | toString | escapeXML }}){{- else }}{{ .Target | toString | escapeXML }}{{ if .Type }} ({{ .Type | toString | escapeXML }}){{ end }}{{- end }}</code></h3>
        {{- if (gt (len .Vulnerabilities) 0) }}
          <h4>Vulnerabilities ({{ len .Vulnerabilities }})</h4>
          <table>
              <tr>
                  <th>Package</th>
                  <th>ID</th>
                  <th>Severity</th>
                  <th>Installed Version</th>
                  <th>Fixed Version</th>
              </tr>
              {{- range .Vulnerabilities }}
                <tr>
                    <td><code>{{ escapeXML .PkgName }}</code></td>
                    <td>{{ escapeXML .VulnerabilityID }}</td>
                    <td>{{ escapeXML .Severity }}</td>
                    <td>{{ escapeXML .InstalledVersion }}</td>
                    <td>{{ escapeXML .FixedVersion }}</td>
                </tr>
              {{- end }}
          </table>
        {{- end }}
        {{- if (gt (len .Misconfigurations ) 0) }}
          <h4>Misconfigurations</h4>
          <table>
              <tr>
                  <th>Type</th>
                  <th>ID</th>
                  <th>Check</th>
                  <th>Severity</th>
                  <th>Message</th>
              </tr>
              {{- range .Misconfigurations }}
                <tr>
                    <td>{{ escapeXML .Type }}</td>
                    <td>{{ escapeXML .ID }}</td>
                    <td>{{ escapeXML .Title }}</td>
                    <td>{{ escapeXML .Severity }}</td>
                    <td>
                      {{ escapeXML .Message }}
                      <br><a href={{ escapeXML .PrimaryURL | printf "%q" }}>{{ escapeXML .PrimaryURL }}</a></br>
                    </td>
                </tr>
              {{- end }}
          </table>
        {{- end }}
      {{- end }}
    {{- end }}
  {{- else }}
    <h3>Empty report</h3>
  {{- end }}
</details>
EOF

echo "[INFO] running Trivy ${TRIVY_VERSION}"
podman run --rm \
    -v ${PODMAN_SOCK}:/var/run/docker.sock \
    -v ${REPORT_FOLDER}:/report \
    docker.io/aquasec/trivy:${TRIVY_VERSION} \
      image \
      --scanners vuln,secret \
      --exit-code 0 \
      --timeout 30m \
      --severity CRITICAL,HIGH \
      --format template --template "@/report/$REPORT_TEMPLATE" -o /report/${REPORT_FILE} \
      ${IMAGE_NAME}

echo "[INFO] writing GitHub step summary"
cat ${REPORT_FOLDER}/${REPORT_FILE} >> ${GITHUB_STEP_SUMMARY}
