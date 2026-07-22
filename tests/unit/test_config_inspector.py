"""
Config Inspector tests — ASVS config_inspection controls (V3.2.1, V3.4.1,
V4.1.1, V5.2.1, V5.3.1). Pure unit tests against ConfigInspector.inspect(),
no pipeline/HTTP/database involved.
"""
from app.domain.analysis.config_inspector import ConfigInspector

GOOD_NGINX = r"""
server {
    listen 443 ssl;
    charset utf-8;
    client_max_body_size 10m;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;

    location /uploads/ {
        add_header Content-Disposition "attachment";
    }
    location ~ \.(php|py|cgi)$ {
        deny all;
    }
}
"""

BAD_NGINX = """
server {
    listen 80;
    location /uploads/ {
        root /var/www/uploads;
        fastcgi_pass 127.0.0.1:9000;
    }
}
"""


def _verdicts(findings):
    return {f.control_id: f.verdict for f in findings}


class TestNginxInspection:
    def test_good_config_passes_all_five_controls(self):
        findings = ConfigInspector().inspect({"nginx.conf": GOOD_NGINX})
        v = _verdicts(findings)
        assert v == {
            "V3.4.1": "pass",
            "V4.1.1": "pass",
            "V5.2.1": "pass",
            "V3.2.1": "pass",
            "V5.3.1": "pass",
        }

    def test_bad_config_fails_all_five_controls(self):
        findings = ConfigInspector().inspect({"nginx.conf": BAD_NGINX})
        v = _verdicts(findings)
        assert v == {
            "V3.4.1": "fail",
            "V4.1.1": "fail",
            "V5.2.1": "fail",
            "V3.2.1": "fail",
            "V5.3.1": "fail",
        }

    def test_hsts_below_one_year_fails(self):
        conf = 'server { add_header Strict-Transport-Security "max-age=3600"; }'
        findings = ConfigInspector().inspect({"nginx.conf": conf})
        hsts = [f for f in findings if f.control_id == "V3.4.1"][0]
        assert hsts.verdict == "fail"

    def test_no_upload_location_produces_no_upload_specific_findings(self):
        conf = "server { listen 443; charset utf-8; client_max_body_size 5m; }"
        findings = ConfigInspector().inspect({"nginx.conf": conf})
        control_ids = {f.control_id for f in findings}
        # No location block resembling upload/media serving -> V3.2.1/V5.3.1 not assessed
        assert "V3.2.1" not in control_ids
        assert "V5.3.1" not in control_ids

    def test_conf_file_detected_by_extension_alone(self):
        # Ensure detection doesn't require the literal word "nginx" in the filename.
        findings = ConfigInspector().inspect({"deploy/reverse-proxy.conf": GOOD_NGINX})
        assert findings, "expected .conf file to be recognized as nginx-style config"


class TestEnvInspection:
    def test_upload_size_env_var_detected(self):
        findings = ConfigInspector().inspect({".env": "MAX_CONTENT_LENGTH=10485760\n"})
        assert any(f.control_id == "V5.2.1" and f.verdict == "pass" for f in findings)

    def test_env_without_size_var_produces_no_finding(self):
        findings = ConfigInspector().inspect({".env": "DEBUG=false\nSECRET_KEY=x\n"})
        assert findings == []


class TestYamlInspection:
    def test_hsts_and_size_found_in_yaml(self):
        yaml_content = "security:\n  hsts_max_age: 63072000\nuploads:\n  max_content_length: 20MB\n"
        findings = ConfigInspector().inspect({"app.yaml": yaml_content})
        v = _verdicts(findings)
        assert v["V3.4.1"] == "pass"
        assert v["V5.2.1"] == "pass"

    def test_hsts_below_threshold_fails_in_yaml(self):
        findings = ConfigInspector().inspect({"app.yaml": "security:\n  hsts_max_age: 3600\n"})
        assert _verdicts(findings)["V3.4.1"] == "fail"

    def test_malformed_yaml_does_not_raise(self):
        findings = ConfigInspector().inspect({"app.yaml": "not: valid: yaml: [["})
        assert findings == []


class TestDockerfileInspection:
    def test_env_size_directive_detected(self):
        dockerfile = "FROM python:3.12\nENV MAX_UPLOAD_SIZE=5242880\nEXPOSE 8000\n"
        findings = ConfigInspector().inspect({"Dockerfile": dockerfile})
        assert any(f.control_id == "V5.2.1" and f.verdict == "pass" for f in findings)

    def test_dockerfile_without_size_env_produces_no_finding(self):
        findings = ConfigInspector().inspect({"Dockerfile": "FROM python:3.12\nEXPOSE 8000\n"})
        assert findings == []


class TestFileRouting:
    def test_unrelated_source_file_produces_no_findings(self):
        findings = ConfigInspector().inspect({"app.py": "def handler(): pass\n"})
        assert findings == []

    def test_multiple_files_all_inspected(self):
        findings = ConfigInspector().inspect({
            "nginx.conf": GOOD_NGINX,
            ".env": "MAX_CONTENT_LENGTH=1000\n",
            "app.py": "x = 1\n",
        })
        files_seen = {f.file for f in findings}
        assert files_seen == {"nginx.conf", ".env"}
