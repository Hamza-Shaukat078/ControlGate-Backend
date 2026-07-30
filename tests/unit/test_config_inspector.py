"""
Config Inspector tests — ASVS config_inspection controls (V3.2.1, V3.4.1,
V3.4.4, V3.4.5, V3.4.6, V4.1.1, V5.2.1, V5.3.1, V13.4.3, V13.4.4, V14.3.2).
Pure unit tests against ConfigInspector.inspect(), no pipeline/HTTP/database
involved.
"""
import json

from app.domain.analysis.config_inspector import ConfigInspector

GOOD_NGINX = r"""
server {
    listen 443 ssl;
    charset utf-8;
    client_max_body_size 10m;
    autoindex off;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer" always;
    add_header Content-Security-Policy "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'" always;
    if ($request_method = TRACE) {
        return 405;
    }

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
    autoindex on;
    location /uploads/ {
        root /var/www/uploads;
        fastcgi_pass 127.0.0.1:9000;
    }
}
"""


def _verdicts(findings):
    return {f.control_id: f.verdict for f in findings}


class TestNginxInspection:
    def test_good_config_passes_all_controls(self):
        findings = ConfigInspector().inspect({"nginx.conf": GOOD_NGINX})
        v = _verdicts(findings)
        assert v == {
            "V3.4.1": "pass",
            "V4.1.1": "pass",
            "V5.2.1": "pass",
            "V3.2.1": "pass",
            "V5.3.1": "pass",
            "V3.4.4": "pass",
            "V3.4.5": "pass",
            "V3.4.6": "pass",
            "V3.4.3": "pass",
            "V13.4.3": "pass",
            "V13.4.4": "pass",
        }

    def test_bad_config_fails_all_controls(self):
        findings = ConfigInspector().inspect({"nginx.conf": BAD_NGINX})
        v = _verdicts(findings)
        assert v == {
            "V3.4.1": "fail",
            "V4.1.1": "fail",
            "V5.2.1": "fail",
            "V3.2.1": "fail",
            "V5.3.1": "fail",
            "V3.4.4": "fail",
            "V3.4.5": "fail",
            "V3.4.6": "fail",
            "V3.4.3": "fail",
            "V13.4.3": "fail",
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

    def test_frame_ancestors_detected_when_not_first_csp_directive(self):
        conf = 'server { add_header Content-Security-Policy "default-src \'self\'; frame-ancestors \'none\'"; }'
        findings = ConfigInspector().inspect({"nginx.conf": conf})
        assert _verdicts(findings)["V3.4.6"] == "pass"

    def test_full_csp_requires_object_src_and_base_uri(self):
        conf = 'server { add_header Content-Security-Policy "default-src \'self\'; frame-ancestors \'none\'"; }'
        findings = ConfigInspector().inspect({"nginx.conf": conf})
        assert _verdicts(findings)["V3.4.3"] == "fail"

    def test_full_csp_policy_passes(self):
        conf = (
            'server { add_header Content-Security-Policy "default-src \'self\'; '
            'object-src \'none\'; base-uri \'none\'; frame-ancestors \'none\'"; }'
        )
        findings = ConfigInspector().inspect({"nginx.conf": conf})
        assert _verdicts(findings)["V3.4.3"] == "pass"

    def test_autoindex_absent_defaults_to_pass(self):
        conf = "server { listen 443; charset utf-8; client_max_body_size 5m; }"
        findings = ConfigInspector().inspect({"nginx.conf": conf})
        assert _verdicts(findings)["V13.4.3"] == "pass"

    def test_limit_except_allowing_trace_fails(self):
        conf = "server { location / { limit_except GET POST TRACE { allow all; } } }"
        findings = ConfigInspector().inspect({"nginx.conf": conf})
        assert _verdicts(findings)["V13.4.4"] == "fail"

    def test_no_trace_handling_produces_no_finding(self):
        conf = "server { listen 443; location / { proxy_pass http://backend; } }"
        findings = ConfigInspector().inspect({"nginx.conf": conf})
        assert "V13.4.4" not in _verdicts(findings)

    def test_sensitive_location_without_no_store_fails(self):
        conf = "server { location /account/ { proxy_pass http://backend; } }"
        findings = ConfigInspector().inspect({"nginx.conf": conf})
        assert _verdicts(findings)["V14.3.2"] == "fail"

    def test_non_sensitive_location_produces_no_cache_control_finding(self):
        conf = "server { location /static/ { proxy_pass http://backend; } }"
        findings = ConfigInspector().inspect({"nginx.conf": conf})
        assert "V14.3.2" not in _verdicts(findings)

    def test_conf_file_detected_by_extension_alone(self):
        # Ensure detection doesn't require the literal word "nginx" in the filename.
        findings = ConfigInspector().inspect({"deploy/reverse-proxy.conf": GOOD_NGINX})
        assert findings, "expected .conf file to be recognized as nginx-style config"


class TestTLSCipherSuiteInspection:
    def test_weak_cipher_token_fails(self):
        conf = 'server { ssl_ciphers "RC4:MD5:HIGH"; }'
        findings = ConfigInspector().inspect({"nginx.conf": conf})
        assert _verdicts(findings)["V12.1.2"] == "fail"

    def test_strong_cipher_suite_passes(self):
        conf = 'server { ssl_ciphers "HIGH:!aNULL:!MD5:!3DES"; }'
        findings = ConfigInspector().inspect({"nginx.conf": conf})
        assert _verdicts(findings)["V12.1.2"] == "pass"

    def test_no_ssl_ciphers_directive_produces_no_finding(self):
        conf = "server { listen 443 ssl; }"
        findings = ConfigInspector().inspect({"nginx.conf": conf})
        assert "V12.1.2" not in _verdicts(findings)


class TestHTTPHTTPSRedirectScopingInspection:
    def test_api_location_redirects_instead_of_rejecting_fails(self):
        conf = """
server {
  listen 80;
  location /api/ {
    return 301 https://$host$request_uri;
  }
}
"""
        findings = ConfigInspector().inspect({"nginx.conf": conf})
        assert _verdicts(findings)["V4.1.2"] == "fail"

    def test_api_location_without_redirect_passes(self):
        conf = """
server {
  listen 80;
  location /api/ {
    return 404;
  }
  location / {
    return 301 https://$host$request_uri;
  }
}
"""
        findings = ConfigInspector().inspect({"nginx.conf": conf})
        assert _verdicts(findings)["V4.1.2"] == "pass"

    def test_no_api_location_produces_no_finding(self):
        conf = """
server {
  listen 80;
  location / {
    return 301 https://$host$request_uri;
  }
}
"""
        findings = ConfigInspector().inspect({"nginx.conf": conf})
        assert "V4.1.2" not in _verdicts(findings)


class TestEgressAllowlistInspection:
    def test_forward_proxy_without_acl_fails(self):
        conf = """
server {
  resolver 8.8.8.8;
  location /proxy/ {
    proxy_pass $scheme://$http_host$request_uri;
  }
}
"""
        findings = ConfigInspector().inspect({"nginx.conf": conf})
        assert _verdicts(findings)["V13.2.5"] == "fail"

    def test_forward_proxy_with_acl_passes(self):
        conf = """
server {
  resolver 8.8.8.8;
  location /proxy/ {
    allow 10.0.0.0/8;
    deny all;
    proxy_pass $scheme://$http_host$request_uri;
  }
}
"""
        findings = ConfigInspector().inspect({"nginx.conf": conf})
        assert _verdicts(findings)["V13.2.5"] == "pass"

    def test_ordinary_reverse_proxy_produces_no_finding(self):
        conf = "server { location / { proxy_pass http://backend; } }"
        findings = ConfigInspector().inspect({"nginx.conf": conf})
        assert "V13.2.5" not in _verdicts(findings)

    def test_k8s_network_policy_with_egress_rules_passes(self):
        yaml_content = """
kind: NetworkPolicy
spec:
  policyTypes:
    - Egress
  egress:
    - to:
        - ipBlock:
            cidr: 10.0.0.0/24
"""
        findings = ConfigInspector().inspect({"netpol.yaml": yaml_content})
        assert _verdicts(findings)["V13.2.5"] == "pass"


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


class TestIAMLeastPrivilegeInspection:
    def test_json_policy_wildcard_action_and_resource_fails_general(self):
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
        })
        findings = ConfigInspector().inspect({"policy.json": policy})
        assert _verdicts(findings)["V13.2.2"] == "fail"

    def test_json_policy_scoped_action_and_resource_passes(self):
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow", "Action": ["s3:GetObject"],
                "Resource": "arn:aws:s3:::my-bucket/*",
            }],
        })
        findings = ConfigInspector().inspect({"policy.json": policy})
        assert _verdicts(findings)["V13.2.2"] == "pass"

    def test_json_policy_wildcard_on_secrets_resource_fails_vault_control(self):
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow", "Action": "*",
                "Resource": "arn:aws:secretsmanager:us-east-1:123:secret:*",
            }],
        })
        findings = ConfigInspector().inspect({"vault-policy.json": policy})
        assert _verdicts(findings)["V13.3.2"] == "fail"

    def test_json_policy_wildcard_resource_logs_action_fails_log_control(self):
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "logs:GetLogEvents", "Resource": "*"}],
        })
        findings = ConfigInspector().inspect({"log-policy.json": policy})
        assert _verdicts(findings)["V16.4.2"] == "fail"

    def test_non_iam_json_produces_no_findings(self):
        findings = ConfigInspector().inspect({"package.json": json.dumps({"name": "app"})})
        assert findings == []

    def test_terraform_wildcard_iam_policy_fails(self):
        tf = """
resource "aws_iam_policy" "bad" {
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}
"""
        findings = ConfigInspector().inspect({"iam.tf": tf})
        assert _verdicts(findings)["V13.2.2"] == "fail"

    def test_terraform_scoped_iam_policy_passes(self):
        tf = """
resource "aws_iam_policy" "good" {
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = "arn:aws:s3:::my-bucket/*"
    }]
  })
}
"""
        findings = ConfigInspector().inspect({"iam.tf": tf})
        assert _verdicts(findings)["V13.2.2"] == "pass"

    def test_terraform_without_iam_resource_produces_no_findings(self):
        tf = 'resource "aws_s3_bucket" "b" { bucket = "my-bucket" }'
        findings = ConfigInspector().inspect({"main.tf": tf})
        assert findings == []

    def test_k8s_clusterrole_wildcard_fails(self):
        role = 'kind: ClusterRole\nrules:\n  - apiGroups: [""]\n    resources: ["*"]\n    verbs: ["*"]\n'
        findings = ConfigInspector().inspect({"role.yaml": role})
        assert _verdicts(findings)["V13.2.2"] == "fail"

    def test_k8s_role_scoped_passes(self):
        role = 'kind: Role\nrules:\n  - apiGroups: [""]\n    resources: ["pods"]\n    verbs: ["get", "list"]\n'
        findings = ConfigInspector().inspect({"role.yaml": role})
        assert _verdicts(findings)["V13.2.2"] == "pass"


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


class TestCoturnInspection:
    GOOD_COTURN = """
listening-port=3478
realm=example.com
denied-peer-ip=10.0.0.0-10.255.255.255
denied-peer-ip=172.16.0.0-172.31.255.255
denied-peer-ip=192.168.0.0-192.168.255.255
denied-peer-ip=127.0.0.0-127.255.255.255
cipher-list="HIGH:!aNULL:!MD5:!3DES"
"""
    BAD_COTURN = """
listening-port=3478
realm=example.com
cipher-list="RC4:MD5"
"""

    def test_good_coturn_passes_both_controls(self):
        findings = ConfigInspector().inspect({"turnserver.conf": self.GOOD_COTURN})
        v = _verdicts(findings)
        assert v["V17.1.1"] == "pass"
        assert v["V17.2.2"] == "pass"

    def test_bad_coturn_fails_both_controls(self):
        findings = ConfigInspector().inspect({"turnserver.conf": self.BAD_COTURN})
        v = _verdicts(findings)
        assert v["V17.1.1"] == "fail"
        assert v["V17.2.2"] == "fail"

    def test_no_cipher_list_directive_produces_no_v1722_finding(self):
        conf = "listening-port=3478\nrealm=example.com\ndenied-peer-ip=10.0.0.0-10.255.255.255\n"
        findings = ConfigInspector().inspect({"turnserver.conf": conf})
        assert "V17.2.2" not in _verdicts(findings)

    def test_detected_via_filename_alone(self):
        findings = ConfigInspector().inspect(
            {"deploy/coturn.conf": "denied-peer-ip=10.0.0.0-10.255.255.255\n"}
        )
        assert _verdicts(findings)["V17.1.1"] == "pass"

    def test_no_loopback_and_no_multicast_partially_satisfies(self):
        conf = "listening-port=3478\nrealm=example.com\nno-loopback-peers\nno-multicast-peers\n"
        findings = ConfigInspector().inspect({"turnserver.conf": conf})
        assert _verdicts(findings)["V17.1.1"] == "pass"

    def test_nginx_conf_is_not_misrouted_to_coturn(self):
        conf = "server { listen 80; location / { proxy_pass http://backend; } }"
        findings = ConfigInspector().inspect({"nginx.conf": conf})
        control_ids = _verdicts(findings)
        assert "V17.1.1" not in control_ids
        assert "V17.2.2" not in control_ids
