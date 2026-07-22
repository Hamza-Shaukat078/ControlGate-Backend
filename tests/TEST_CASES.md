# Vulcan Backend — Complete Test Case Documentation

> **Total: 354 test functions · ~420 expanded instances (parametrized)**  
> Run: `pytest tests/ -v` — all tests collected automatically.

---

## Table of Contents

1. [Unit Tests (UT-001 – UT-168)](#1-unit-tests)
   - [1.1 Security Module](#11-security-module--test_securitypy)
   - [1.2 Benchmark Metrics](#12-benchmark-metrics--test_benchmark_metricspy)
   - [1.3 Kill Chain Logic](#13-kill-chain-logic--test_kill_chain_logicpy)
   - [1.4 Query Patterns](#14-query-patterns--test_query_patternspy)
   - [1.5 Legacy AST / DFG](#15-legacy-ast--dfg-tests)
   - [1.6 Patch — Diff Utils](#16-patch-module--diff-utils)
   - [1.7 Patch — Guards](#17-patch-module--guards)
   - [1.8 Patch — Syntax Validator](#18-patch-module--syntax-validator)
   - [1.9 Patch — Semantic Validator](#19-patch-module--semantic-validator)
   - [1.10 Patch — Prompt Builder](#110-patch-module--prompt-builder)
   - [1.11 Patch — Patch Repository](#111-patch-module--patch-repository)
   - [1.12 Patch — LLM Service](#112-patch-module--llm-service)
   - [1.13 Patch — Orchestrator](#113-patch-module--orchestrator)
2. [Integration Tests (IT-001 – IT-107)](#2-integration-tests)
   - [2.1 Auth API](#21-auth-api--test_auth_apipy)
   - [2.2 Scan API](#22-scan-api--test_scan_apipy)
   - [2.3 Benchmark API](#23-benchmark-api--test_benchmark_apipy)
   - [2.4 Kill Chain API](#24-kill-chain-api--test_kill_chain_apipy)
   - [2.5 Repositories API](#25-repositories-api--test_repositories_apipy)
3. [Functional Tests (FT-001 – FT-012)](#3-functional-tests)
4. [Business Rule Tests (BR-001 – BR-123)](#4-business-rule-tests)
   - [4.1 Role-Based Access Control](#41-role-based-access-control--test_role_accesspy)
   - [4.2 Vulnerability Detection](#42-vulnerability-detection--test_vulnerability_detectionpy)
   - [4.3 Benchmark Scoring](#43-benchmark-scoring--test_benchmark_scoringpy)
5. [Summary](#5-summary)
6. [How to Run](#6-how-to-run)

---

## 1. Unit Tests

### 1.1 Security Module — `test_security.py`

| Test ID | Function | Description | Input | Expected Output |
|---------|----------|-------------|-------|-----------------|
| UT-001 | `test_hash_is_not_plaintext` | Hashed password must not equal original | `"password"` | `hash != "password"` |
| UT-002 | `test_hash_starts_with_bcrypt_prefix` | bcrypt output has `$2b$` prefix | `"password"` | hash starts with `$2b$` |
| UT-003 | `test_same_password_different_hashes` | Same input produces different salted hashes | `"password"` twice | hash1 != hash2 |
| UT-004 | `test_verify_correct_password` | Correct password passes verification | `"password"`, bcrypt hash | `True` |
| UT-005 | `test_verify_wrong_password` | Wrong password fails verification | `"wrong"`, bcrypt hash | `False` |
| UT-006 | `test_verify_empty_password_fails` | Empty string does not match hash | `""`, bcrypt hash | `False` |
| UT-007 | `test_hash_empty_string` | Empty string can still be hashed | `""` | valid bcrypt hash |
| UT-008 | `test_unicode_password` | Unicode passwords are hashed correctly | `"passworld"` (unicode) | valid bcrypt hash, verifies True |
| UT-009 | `test_access_token_is_string` | `create_access_token` returns a string | user_id `"u1"` | `isinstance(token, str)` |
| UT-010 | `test_token_contains_subject` | JWT payload contains the subject claim | user_id `"u1"` | `payload["sub"] == "u1"` |
| UT-011 | `test_integer_subject_coerced_to_string` | Integer user_id is coerced to string | user_id `42` | `payload["sub"] == "42"` |
| UT-012 | `test_extra_claims_present_in_payload` | Extra claims are embedded in JWT | `extra_claims={"role": "admin"}` | `payload["role"] == "admin"` |
| UT-013 | `test_multiple_extra_claims` | Multiple extra claims all survive round-trip | `{"role": "admin", "plan": "pro"}` | both keys present in payload |
| UT-014 | `test_access_token_has_iat_and_exp` | JWT contains `iat` and `exp` standard claims | any user_id | `"iat" in payload and "exp" in payload` |
| UT-015 | `test_exp_is_in_future` | Expiry timestamp is in the future | any user_id | `payload["exp"] > now()` |
| UT-016 | `test_refresh_token_has_longer_expiry_than_access` | Refresh token lives longer than access token | same user_id | `refresh_exp > access_exp` |
| UT-017 | `test_custom_expiry_minutes` | Custom `expires_delta` is respected | `expires_delta=timedelta(minutes=1)` | exp within ~60 s of now |
| UT-018 | `test_valid_token_decodes` | Well-formed token decodes without error | valid token | `payload["sub"]` returns user_id |
| UT-019 | `test_tampered_token_raises` | Flipping a byte in token raises JWTError | tampered token string | `JWTError` raised |
| UT-020 | `test_wrong_secret_raises` | Token signed with wrong secret is rejected | foreign-secret token | `JWTError` raised |
| UT-021 | `test_expired_token_raises` | Expired token raises JWTError | token with past `exp` | `JWTError` raised |
| UT-022 | `test_malformed_token_raises` | Garbage string raises JWTError | `"not.a.token"` | `JWTError` raised |
| UT-023 | `test_empty_token_raises` | Empty string raises JWTError | `""` | `JWTError` raised |

---

### 1.2 Benchmark Metrics — `test_benchmark_metrics.py`

| Test ID | Function | Description | Input (tp, fp, fn, tn) | Expected Output |
|---------|----------|-------------|------------------------|-----------------|
| UT-024 | `test_all_true_positives` | All TPs: precision, recall, F1 all 1.0 | (10, 0, 0, 0) | p=1.0, r=1.0, f1=1.0 |
| UT-025 | `test_all_true_negatives` | All TNs: metrics are 0 or safe | (0, 0, 0, 10) | p=0.0, r=0.0, f1=0.0 |
| UT-026 | `test_all_zeros_returns_zeros` | No data: all metrics zero | (0, 0, 0, 0) | all 0.0, no exception |
| UT-027 | `test_zero_tp_zero_fp_no_division_error` | No predictions: no division error | (0, 0, 5, 5) | no exception, f1=0.0 |
| UT-028 | `test_zero_fp_zero_tn_no_division_error` | No negatives: FP rate safe | (5, 0, 5, 0) | no exception, fpr=0.0 |
| UT-029 | `test_standard_benchmark_scenario` | Mixed realistic results | (8, 2, 3, 7) | 0 < p < 1, 0 < r < 1 |
| UT-030 | `test_high_fp_rate_scenario` | Many FPs: high FP rate | (5, 15, 2, 3) | fpr > 0.7 |
| UT-031 | `test_high_fn_low_recall` | Many FNs: recall near zero | (1, 0, 20, 0) | r approx 0.048 |
| UT-032 | `test_equal_tp_fp_fn` | Equal TP/FP/FN: balanced scenario | (5, 5, 5, 5) | p=0.5, r=0.5 |
| UT-033 | `test_values_rounded_to_4_decimal_places` | Results have <= 4 decimal digits | (7, 3, 4, 6) | `round(p, 4) == p` |
| UT-034 | `test_returns_four_values` | Function returns exactly 4 values | any valid input | tuple length == 4 |
| UT-035 | `test_all_values_between_zero_and_one` | All metrics in [0.0, 1.0] | (7, 3, 4, 6) | 0 <= each value <= 1 |
| UT-036 | `test_f1_is_harmonic_mean_of_precision_recall` | F1 = 2*p*r/(p+r) | (6, 4, 4, 6) | f1 == harmonic mean |
| UT-037 | `test_f1_zero_when_no_true_positives` | No TPs -> F1 is 0 | (0, 5, 5, 5) | f1 == 0.0 |
| UT-038 | `test_f1_bounded_by_precision_and_recall` | F1 <= min(p, r) | (2, 8, 8, 2) | f1 <= min(p, r) |

---

### 1.3 Kill Chain Logic — `test_kill_chain_logic.py`

| Test ID | Function | Description | Input | Expected Output |
|---------|----------|-------------|-------|-----------------|
| UT-039 | `test_sql_injection_maps_to_initial_access` | SQL Injection -> initial_access stage | `"SQL Injection"` | `"initial_access"` |
| UT-040 | `test_command_injection_maps_to_execution` | Command Injection -> execution stage | `"Command Injection"` | `"execution"` |
| UT-041 | `test_path_traversal_maps_to_persistence` | Path Traversal -> persistence stage | `"Path Traversal"` | `"persistence"` |
| UT-042 | `test_xss_maps_to_exfiltration` | XSS -> exfiltration stage | `"XSS"` | `"exfiltration"` |
| UT-043 | `test_hardcoded_secret_maps_to_credential_access` | Hardcoded Secret -> credential_access | `"Hardcoded Secret"` | `"credential_access"` |
| UT-044 | `test_broken_access_control_maps_to_privilege_escalation` | BAC -> privilege_escalation | `"Broken Access Control"` | `"privilege_escalation"` |
| UT-045 | `test_sensitive_data_exposure_maps_to_reconnaissance` | Sensitive Data -> reconnaissance | `"Sensitive Data Exposure"` | `"reconnaissance"` |
| UT-046 | `test_denial_of_service_maps_to_impact` | DoS -> impact | `"Denial of Service"` | `"impact"` |
| UT-047 | `test_ssrf_maps_to_initial_access` | SSRF -> initial_access | `"SSRF"` | `"initial_access"` |
| UT-048 | `test_ssti_maps_to_execution` | SSTI -> execution | `"SSTI"` | `"execution"` |
| UT-049 | `test_unknown_type_defaults_to_reconnaissance` | Unknown type -> reconnaissance | `"Unknown Vuln"` | `"reconnaissance"` |
| UT-050 | `test_empty_string_defaults_to_reconnaissance` | Empty string -> reconnaissance | `""` | `"reconnaissance"` |
| UT-051 | `test_none_defaults_to_reconnaissance` | None -> reconnaissance | `None` | `"reconnaissance"` |
| UT-052 | `test_case_insensitive` | Mapping is case-insensitive | `"sql injection"` | `"initial_access"` |
| UT-053 | `test_partial_match_works` | Substring match maps correctly | `"sqli attack"` | `"initial_access"` |
| UT-054 | `test_insecure_deserialization_maps_to_execution` | Insecure Deserialization -> execution | `"Insecure Deserialization"` | `"execution"` |
| UT-055 | `test_weak_cryptography_maps_to_credential_access` | Weak Crypto -> credential_access | `"Weak Cryptography"` | `"credential_access"` |
| UT-056 | `test_no_vulns_returns_zero` | No vulnerabilities -> blast radius 0 | `[]` | `0` |
| UT-057 | `test_single_critical_vuln` | One critical vuln -> non-zero radius | `[{severity:"critical"}]` | `> 0` |
| UT-058 | `test_execution_stage_adds_bonus` | Execution stage adds bonus points | Command Injection high severity | higher than non-execution |
| UT-059 | `test_impact_stage_adds_bonus` | Impact stage adds bonus points | Denial of Service high severity | higher than non-impact |
| UT-060 | `test_more_stages_higher_radius` | More ATT&CK stages -> higher radius | 1 stage vs 4 stages | 4-stage radius > 1-stage |
| UT-061 | `test_result_capped_at_100` | Blast radius is capped at 100 | many critical vulns | `result <= 100` |
| UT-062 | `test_result_is_integer` | Result is an integer type | any vulns list | `isinstance(result, int)` |
| UT-063 | `test_critical_higher_than_low` | Critical severity -> higher radius than low | critical vs low | critical_radius > low_radius |
| UT-064 | `test_no_active_stages_returns_empty` | No staged vulns -> empty kill chains | stages dict all empty | `chains == []` |
| UT-065 | `test_single_stage_returns_empty` | Only one stage -> no chain possible | one stage active | `chains == []` |
| UT-066 | `test_two_matching_stages_returns_chain` | Two adjacent stages -> one chain | recon + initial_access | `len(chains) == 1` |
| UT-067 | `test_all_stages_active_returns_up_to_4_chains` | 8 active stages -> at most 4 chains | all 8 stages | `len(chains) <= 4` |
| UT-068 | `test_chains_sorted_by_probability_descending` | Chains ordered highest probability first | multiple chains | probs descending |
| UT-069 | `test_each_chain_has_required_keys` | Each chain dict has required fields | any chains | `"stages"`, `"probability"` present |
| UT-070 | `test_probability_between_0_and_1` | Chain probability is valid | any chains | `0 <= p <= 1` |
| UT-071 | `test_no_vulns_returns_secure_message` | Empty vuln list -> "no vulnerabilities" narrative | `[]` | string mentions "no" or "secure" |
| UT-072 | `test_narrative_includes_blast_radius` | Narrative embeds blast radius number | vulns with radius 75 | `"75"` in text |
| UT-073 | `test_narrative_mentions_initial_access_vuln_type` | Narrative references initial_access vuln type | SQL Injection vuln | `"SQL"` in narrative |
| UT-074 | `test_narrative_mentions_execution` | Narrative mentions execution when present | Command Injection vuln | `"execution"` in narrative |
| UT-075 | `test_narrative_mentions_credential_harvesting` | Narrative mentions credentials when present | Hardcoded Secret vuln | credential mention in text |
| UT-076 | `test_narrative_is_nonempty_string` | Narrative is always a non-empty string | any vulns | `len(narrative) > 0` |
| UT-077 | `test_high_blast_radius_reflected` | High radius reflected in narrative tone | radius = 90 | warning language in text |

---

### 1.4 Query Patterns — `test_query_patterns.py`

| Test ID | Function | Rule | Code Sample | Expected |
|---------|----------|------|-------------|----------|
| UT-078 | `test_fstring_query_detected` | SQL_INJECTION | `f"SELECT * FROM users WHERE id={user_id}"` | detected |
| UT-079 | `test_string_concat_detected` | SQL_INJECTION | `"SELECT * FROM users WHERE name=" + name` | detected |
| UT-080 | `test_parameterized_query_not_detected` | SQL_INJECTION | `cursor.execute("SELECT...", (uid,))` | not detected |
| UT-081 | `test_os_system_detected` | COMMAND_INJECTION | `os.system(user_cmd)` | detected |
| UT-082 | `test_shell_true_detected` | COMMAND_INJECTION | `subprocess.run(cmd, shell=True)` | detected |
| UT-083 | `test_child_process_exec_detected` | COMMAND_INJECTION | `child_process.exec(req.body.cmd)` | detected |
| UT-084 | `test_execsync_detected` | COMMAND_INJECTION | `child_process.execSync(userInput)` | detected |
| UT-085 | `test_safe_list_form_not_detected` | COMMAND_INJECTION | `subprocess.run(["ls", "-la"])` | not detected |
| UT-086 | `test_os_popen_detected` | COMMAND_INJECTION | `os.popen(cmd)` | detected |
| UT-087 | `test_open_with_plus_detected` | PATH_TRAVERSAL | `open("/uploads/" + filename)` | detected |
| UT-088 | `test_open_with_user_param_detected` | PATH_TRAVERSAL | `open(user_file, "r")` | detected |
| UT-089 | `test_send_file_with_request_args_detected` | PATH_TRAVERSAL | `send_file(request.args.get('name'))` | detected |
| UT-090 | `test_js_path_join_with_req_query_detected` | PATH_TRAVERSAL | `path.join(__dirname, req.params.name)` | detected |
| UT-091 | `test_safe_static_path_not_detected` | PATH_TRAVERSAL | `open("/var/app/config.json", "r")` | not detected |
| UT-092 | `test_pickle_loads_detected` | INSECURE_DESERIALIZATION | `pickle.loads(data)` | detected |
| UT-093 | `test_yaml_load_without_safeloader_detected` | INSECURE_DESERIALIZATION | `yaml.load(stream)` | detected |
| UT-094 | `test_yaml_load_with_safeloader_not_detected` | INSECURE_DESERIALIZATION | `yaml.load(data, Loader=SafeLoader)` | not detected |
| UT-095 | `test_yaml_safe_load_not_detected` | INSECURE_DESERIALIZATION | `yaml.safe_load(data)` | not detected |
| UT-096 | `test_json_parse_not_detected` | INSECURE_DESERIALIZATION | `JSON.parse(body)` | not detected |
| UT-097 | `test_marshal_loads_detected` | INSECURE_DESERIALIZATION | `marshal.loads(raw)` | detected |
| UT-098 | `test_jsonpickle_decode_detected` | INSECURE_DESERIALIZATION | `jsonpickle.decode(payload)` | detected |
| UT-099 | `test_hashlib_md5_detected` | WEAK_CRYPTO | `hashlib.md5(data.encode()).hexdigest()` | detected |
| UT-100 | `test_hashlib_sha1_detected` | WEAK_CRYPTO | `hashlib.sha1(password)` | detected |
| UT-101 | `test_createhash_md5_detected` | WEAK_CRYPTO | `crypto.createHash('md5')` | detected |
| UT-102 | `test_rsa_generate_1024_detected` | WEAK_CRYPTO | `RSA.generate(1024)` | detected |
| UT-103 | `test_rsa_generate_512_detected` | WEAK_CRYPTO | `RSA.generate(512)` | detected |
| UT-104 | `test_key_size_1024_detected` | WEAK_CRYPTO | `key_size=1024` | detected |
| UT-105 | `test_rsa_generate_4096_not_detected` | WEAK_CRYPTO | `RSA.generate(4096)` | not detected |
| UT-106 | `test_hashlib_sha256_not_detected` | WEAK_CRYPTO | `hashlib.sha256(data)` | not detected |
| UT-107 | `test_jwt_secret_string_detected` | HARDCODED_SECRETS | `JWT_SECRET = "my-hardcoded-secret"` | detected |
| UT-108 | `test_api_key_assignment_detected` | HARDCODED_SECRETS | `api_key = "sk-1234567890abcdef"` | detected |
| UT-109 | `test_password_variable_detected` | HARDCODED_SECRETS | `password = "admin123"` | detected |
| UT-110 | `test_env_var_lookup_not_detected` | HARDCODED_SECRETS | `secret = os.environ.get("JWT_SECRET")` | not detected |
| UT-111 | `test_requests_get_with_request_args_detected` | SSRF | `requests.get(request.args.get('url'))` | detected |
| UT-112 | `test_requests_get_with_static_url_not_detected` | SSRF | `requests.get("https://api.example.com/data")` | not detected |
| UT-113 | `test_urllib_with_req_body_detected` | SSRF | `urllib.request.urlopen(req.query.url)` | detected |
| UT-114 | `test_app_run_debug_true_detected` | INFORMATION_EXPOSURE_ERROR | `app.run(debug=True)` | detected |
| UT-115 | `test_app_run_debug_false_not_detected` | INFORMATION_EXPOSURE_ERROR | `app.run(debug=False)` | not detected |
| UT-116 | `test_debug_equals_true_standalone_detected` | INFORMATION_EXPOSURE_ERROR | `DEBUG = True` | detected |
| UT-117 | `test_set_cookie_without_secure_detected` | INSECURE_COOKIE | `set_cookie('session', token)` | detected |
| UT-118 | `test_set_cookie_with_secure_true_not_detected` | INSECURE_COOKIE | `set_cookie('session', token, secure=True)` | not detected |
| UT-119 | `test_res_cookie_without_secure_detected` | INSECURE_COOKIE | `res.cookie('session', token)` | detected |
| UT-120 | `test_res_cookie_with_secure_true_not_detected` | INSECURE_COOKIE | `res.cookie('auth', val, { secure: true, httpOnly: true })` | not detected |
| UT-121 | `test_res_redirect_with_req_query_detected` | UNVALIDATED_REDIRECT | `res.redirect(req.query.next)` | detected |
| UT-122 | `test_flask_redirect_with_request_args_detected` | UNVALIDATED_REDIRECT | `redirect(request.args.get('url'))` | detected |
| UT-123 | `test_static_redirect_not_detected` | UNVALIDATED_REDIRECT | `res.redirect("/dashboard")` | not detected |

---

### 1.5 Legacy AST / DFG Tests

| Test ID | File | Function | Description | Expected |
|---------|------|----------|-------------|----------|
| UT-124 | `test_js_flows.py` | `test_callback_flow` | CPG parser produces DFG_CALLBACK edges for JS callback pattern | callback DFG edges present |
| UT-125 | `test_js_flows.py` | `test_closure_capture` | CPG parser produces DFG_CLOSURE edges for JS closure capture | closure DFG edges present |
| UT-126 | `test_cross_file_flow.py` | `test_import_export_flow` | Cross-file graph produces IMPORT_CALL + DFG_IMPORT edges between a.js and b.js | both edge types present |
| UT-127 | `test_cross_file_flow.py` | `test_cross_file_two_hop` | Reexport through b.js: a->b->c produces DFG_IMPORT edges | DFG_IMPORT edges present |
| UT-128 | `test_commonjs_exports.py` | `test_module_exports_function` | `module.exports = fn` is tracked as an export | exports count >= 1 |
| UT-129 | `test_commonjs_exports.py` | `test_exports_assignment` | `exports = fn` is tracked as an export | exports count >= 1 |
| UT-130 | `test_import_export_patterns.py` | `test_ts_import_equals` | TypeScript `import x = require('./a')` produces an import | imports count >= 1 |
| UT-131 | `test_import_export_patterns.py` | `test_commonjs_exports_assignment` | `module.exports = f` is tracked | exports count >= 1 |
| UT-132 | `test_reexport_chain.py` | `test_reexport_chain` | Three-hop `export * from` chain resolves to original symbol in c.js | `a` symbol found in c.js exports |
| UT-133 | `test_ts_export_equals.py` | `test_ts_export_equals_import_equals` | TS `export = value` + `import x = require('./a')` round-trip | imports >= 1, exports >= 1 |

---

### 1.6 Patch Module — Diff Utils

| Test ID | Function | Description | Input | Expected |
|---------|----------|-------------|-------|----------|
| UT-134 | `test_valid_diff` | Well-formed unified diff parsed correctly | single-file diff with one hunk | target file ends with `app.py`, added=1, removed=1 |
| UT-135 | `test_multi_file_diff_rejected` | Diff touching two files raises error | 2-file diff | `PatchValidationError` raised |
| UT-136 | `test_no_hunks_rejected` | Diff with header but no hunks raises error | header-only diff | `PatchValidationError` raised |
| UT-137 | `test_markdown_fenced_diff` | Markdown-fenced diff block is normalized | ` ```diff ... ``` ` block | parsed correctly, target file set |

---

### 1.7 Patch Module — Guards

| Test ID | Function | Description | Input | Expected |
|---------|----------|-------------|-------|----------|
| UT-138 | `test_enforce_slice_length` | Code slice > 200 lines raises ValidationException | 201-line string | `ValidationException` raised |
| UT-139 | `test_reject_secrets` | AKIA-prefixed key pattern raises ValidationException | `"AKIA" + "A"*16` | `ValidationException` raised |
| UT-140 | `test_enforce_rate_limit` | 11th call within window raises RateLimitException | 11 calls for same user | `RateLimitException` on call 11 |

---

### 1.8 Patch Module — Syntax Validator

| Test ID | Function | Description | Input | Expected |
|---------|----------|-------------|-------|----------|
| UT-141 | `test_python_syntax_valid` | Valid Python patch passes syntax check | `print('ok')` -> `print('fixed')` diff | `result.passed == True` |
| UT-142 | `test_python_syntax_invalid` | Invalid Python patch (unclosed paren) fails | `print('ok')` -> `print('bad'` diff | `result.passed == False` |
| UT-143 | `test_js_syntax_valid_or_unverified` | Valid JS patch passes or is unverified | `const a = 1` -> `const a = 2` diff | `result.passed == True` |
| UT-144 | `test_js_syntax_invalid_if_parser_available` | Invalid JS raises syntax error if esprima present | `const a = ;` diff | `result.passed in (True, False)` |

---

### 1.9 Patch Module — Semantic Validator

| Test ID | Function | Description | Patched Slice | Expected |
|---------|----------|-------------|---------------|----------|
| UT-145 | `test_semantic_sqli_pass` | Parameterized query passes SQLi semantic check | `cursor.execute("SELECT...", (user_id,))` | `passed == True` |
| UT-146 | `test_semantic_sqli_fail` | f-string query fails SQLi semantic check | `f"SELECT ... {user_id}"` + execute | `passed == False` |
| UT-147 | `test_semantic_xss_pass` | `textContent` assignment passes XSS check | `element.textContent = userInput` | `passed == True` |
| UT-148 | `test_semantic_xss_fail` | `innerHTML` assignment fails XSS check | `element.innerHTML = userInput` | `passed == False` |
| UT-149 | `test_semantic_command_injection_pass` | List-form subprocess passes CMDi check | `subprocess.run(["ping", host], shell=False)` | `passed == True` |
| UT-150 | `test_semantic_command_injection_fail` | `os.system` concatenation fails CMDi check | `os.system("ping -c 1 " + host)` | `passed == False` |

---

### 1.10 Patch Module — Prompt Builder

| Test ID | Function | Description | Expected |
|---------|----------|-------------|----------|
| UT-151 | `test_prompt_builder_sqli_python` | Basic prompt contains diff instruction and vulnerable slice | `"YOUR ONLY OUTPUT IS A VALID UNIFIED DIFF"` and slice present |
| UT-152 | `test_build_cot_reasoning_prompt_structure` | CoT reasoning prompt has ROOT CAUSE, ATTACK VECTOR, AFFECTED LINES, SECURE REPLACEMENT, IMPORTS NEEDED but no diff markers | all sections present, no `--- a/` |
| UT-153 | `test_build_cot_reasoning_prompt_no_diff_output` | Reasoning prompt explicitly says no diff | `"no diff"` or `"not a diff"` in prompt |
| UT-154 | `test_build_industrial_cot_prompt_four_phases` | Industrial CoT has 4 phases, PATCH_SPEC block, BYPASS_FOUND, CVSS | all markers present, no diff markers |
| UT-155 | `test_build_industrial_cot_prompt_exploit_requirement` | Industrial CoT requests CONCRETE EXPLOIT, ATTACK SURFACE, BREAKAGE_RISK, NEW_IMPORT | all four strings present |
| UT-156 | `test_prompt_builder_xss_js` | XSS JS prompt mentions innerHTML and suggests DOMPurify/textContent | both present |

---

### 1.11 Patch Module — Patch Repository

| Test ID | Function | Description | Expected |
|---------|----------|-------------|----------|
| UT-157 | `test_patch_repository_crud` | Create, get, update, list patch lifecycle via FakeDB | patch_id set; get returns patch; update returns True; list returns 1 |
| UT-158 | `test_patch_repository_pending_apply_and_rate_limit` | Pending apply created; rate limit counter increments | pending_id set; count == 1 |

---

### 1.12 Patch Module — LLM Service

| Test ID | Function | Description | Expected |
|---------|----------|-------------|----------|
| UT-159 | `test_generate_patch_valid_diff` | OpenAI returns markdown-fenced diff; stripped and returned clean | result starts with `--- `, no backticks |
| UT-160 | `test_generate_patch_invalid_diff` | OpenAI returns non-diff text; returned as-is | result equals bad_text |
| UT-161 | `test_generate_patch_empty_fallback` | Both providers return empty; offline template returned | `PLACEHOLDER_FILE` in result |
| UT-162 | `test_generate_patch_with_cot_success` | CoT: reasoning call then diff call; reasoning injected as assistant turn | 2 calls made, result starts with `--- ` |
| UT-163 | `test_generate_patch_with_cot_reasoning_fails_fallback` | CoT reasoning returns empty; falls back to direct generate_patch | fallback called with diff prompt |
| UT-164 | `test_generate_patch_with_cot_diff_step_fails` | CoT reasoning succeeds but diff step returns empty; offline template used | `PLACEHOLDER_FILE` in result |
| UT-165 | `test_generate_patch_with_cot_reasoning_in_diff_context` | Reasoning text injected as assistant turn in diff call | roles=[system, user, assistant, user]; REASONING in assistant content |

---

### 1.13 Patch Module — Orchestrator

| Test ID | Function | Description | Expected |
|---------|----------|-------------|----------|
| UT-166 | `test_orchestrator_generate_with_context` | End-to-end generate: builds prompt, calls LLM, stores patch in FakeDB | patch_id set, diff starts with `--- `, stored in repo |
| UT-167 | `test_orchestrator_uses_cot_on_first_attempt` | First attempt uses `generate_patch_with_industrial_cot`; no direct fallback | cot_calls==1, direct_calls==0, generation_attempts==1 |
| UT-168 | `test_orchestrator_retries_use_direct_generate` | Failed CoT diff triggers retry via `generate_patch` | cot_calls==1, direct_calls>=1, generation_attempts>=2 |

---

## 2. Integration Tests

### 2.1 Auth API — `test_auth_api.py`

| Test ID | Function | Description | Request | Expected |
|---------|----------|-------------|---------|----------|
| IT-001 | `test_register_new_user_returns_201` | Register with valid email+password | `POST /api/v1/auth/register` | HTTP 201 |
| IT-002 | `test_register_returns_user_fields` | Response has id, email, role, is_active | `POST /api/v1/auth/register` | all fields present |
| IT-003 | `test_register_default_role_is_normal` | New users default to role=normal | `POST /api/v1/auth/register` | `role == "normal"` |
| IT-004 | `test_register_duplicate_email_returns_409` | Second registration with same email | `POST /api/v1/auth/register` (dupe) | HTTP 409 |
| IT-005 | `test_register_missing_email_returns_422` | Missing email field | `POST /api/v1/auth/register` | HTTP 422 |
| IT-006 | `test_register_missing_password_returns_422` | Missing password field | `POST /api/v1/auth/register` | HTTP 422 |
| IT-007 | `test_register_invalid_email_format_returns_422` | `notanemail` as email | `POST /api/v1/auth/register` | HTTP 422 |
| IT-008 | `test_register_optional_full_name` | Omitting full_name succeeds | `POST /api/v1/auth/register` (no full_name) | HTTP 201 |
| IT-009 | `test_register_with_full_name` | full_name is stored and returned | `POST /api/v1/auth/register` (with full_name) | full_name in response |
| IT-010 | `test_login_valid_credentials_returns_200` | Login with correct credentials | `POST /api/v1/auth/login` | HTTP 200 |
| IT-011 | `test_login_returns_access_token` | Response body contains access_token | `POST /api/v1/auth/login` | `access_token` key present |
| IT-012 | `test_login_returns_token_type_bearer` | token_type is "bearer" | `POST /api/v1/auth/login` | `token_type == "bearer"` |
| IT-013 | `test_login_wrong_password_returns_401` | Wrong password rejected | `POST /api/v1/auth/login` (bad pass) | HTTP 401 |
| IT-014 | `test_login_nonexistent_user_returns_401` | Non-existent user rejected | `POST /api/v1/auth/login` (unknown) | HTTP 401 |
| IT-015 | `test_login_empty_password_returns_401_or_422` | Empty password rejected | `POST /api/v1/auth/login` (empty pass) | HTTP 401 or 422 |
| IT-016 | `test_login_missing_fields_returns_422` | Missing fields in login body | `POST /api/v1/auth/login` (no body) | HTTP 422 |
| IT-017 | `test_me_authenticated_returns_200` | /me with valid token returns 200 | `GET /api/v1/auth/me` (bearer) | HTTP 200 |
| IT-018 | `test_me_returns_correct_email` | /me returns the authenticated user's email | `GET /api/v1/auth/me` | email matches registered user |
| IT-019 | `test_me_returns_role` | /me includes role field | `GET /api/v1/auth/me` | `role` key present |
| IT-020 | `test_me_does_not_return_hashed_password` | /me must not expose hashed_password | `GET /api/v1/auth/me` | `hashed_password` absent |
| IT-021 | `test_me_unauthenticated_returns_401` | /me without token returns 401 | `GET /api/v1/auth/me` (no token) | HTTP 401 |
| IT-022 | `test_refresh_authenticated_returns_new_token` | Refresh with valid token returns 200 | `POST /api/v1/auth/refresh` | HTTP 200 |
| IT-023 | `test_refresh_returns_different_token` | Second refresh returns a new token string | two refresh calls | token1 != token2 |
| IT-024 | `test_logout_authenticated_returns_200` | Logout with valid token returns 200 | `POST /api/v1/auth/logout` | HTTP 200 |
| IT-025 | `test_logout_returns_message` | Logout response has message field | `POST /api/v1/auth/logout` | `message` key in response |
| IT-026 | `test_forgot_password_returns_200_always` | Forgot password always returns 200 (no user enumeration) | `POST /api/v1/auth/forgot-password` (unknown email) | HTTP 200 |
| IT-027 | `test_forgot_password_registered_email_returns_200` | Forgot password for registered email also returns 200 | `POST /api/v1/auth/forgot-password` (known email) | HTTP 200 |
| IT-028 | `test_validate_invalid_token_returns_false` | Validate endpoint rejects fake token | `GET /api/v1/auth/validate?token=badtoken` | `valid == false` |
| IT-029 | `test_reset_invalid_token_returns_400` | Reset with invalid token is rejected | `POST /api/v1/auth/reset-password` (bad token) | HTTP 400 |

---

### 2.2 Scan API — `test_scan_api.py`

| Test ID | Function | Description | Request | Expected |
|---------|----------|-------------|---------|----------|
| IT-030 | `test_scan_clean_code_returns_200` | Clean Python code scanned successfully | `POST /api/v1/scan/scan` (clean code) | HTTP 200 |
| IT-031 | `test_scan_vulnerable_code_returns_findings` | SQLi code returns vulnerability findings | `POST /api/v1/scan/scan` (SQLi code) | `vulnerabilities` list non-empty |
| IT-032 | `test_scan_missing_code_returns_422` | Missing code field in body | `POST /api/v1/scan/scan` (no code) | HTTP 422 |
| IT-033 | `test_scan_missing_language_returns_422` | Missing language field in body | `POST /api/v1/scan/scan` (no language) | HTTP 422 |
| IT-034 | `test_scan_response_has_scan_id` | Scan response includes scan_id | `POST /api/v1/scan/scan` | `scan_id` key present |
| IT-035 | `test_scan_response_has_severity_breakdown` | Response includes severity breakdown | `POST /api/v1/scan/scan` | `severity_breakdown` dict present |
| IT-036 | `test_scan_javascript_code` | JavaScript code is accepted | `POST /api/v1/scan/scan` (JS code) | HTTP 200 |
| IT-037 | `test_scan_unauthenticated_returns_401` | Scan without auth token rejected | `POST /api/v1/scan/scan` (no token) | HTTP 401 |
| IT-038 | `test_get_existing_scan_status` | Get status of completed scan | `GET /api/v1/scans/{scan_id}` | HTTP 200 |
| IT-039 | `test_get_nonexistent_scan_returns_404` | Get status of unknown scan_id | `GET /api/v1/scans/nonexistent` | HTTP 404 |
| IT-040 | `test_status_response_has_status_field` | Scan status response has `status` key | `GET /api/v1/scans/{scan_id}` | `status` key present |
| IT-041 | `test_completed_scan_status_is_completed` | Pre-seeded COMPLETED scan reports COMPLETED | `GET /api/v1/scans/{scan_id}` | `status == "COMPLETED"` |
| IT-042 | `test_list_scans_returns_200` | Scan list endpoint returns 200 | `GET /api/v1/scans/` | HTTP 200 |
| IT-043 | `test_list_scans_returns_list` | Scan list response is an array | `GET /api/v1/scans/` | `isinstance(body, list)` |
| IT-044 | `test_completed_scan_appears_in_list` | Seeded scan appears in the list | `GET /api/v1/scans/` | seeded scan_id in list |
| IT-045 | `test_list_scan_unauthenticated_returns_401` | Unauthenticated scan list rejected | `GET /api/v1/scans/` (no token) | HTTP 401 |
| IT-046 | `test_delete_existing_scan_returns_200_or_204` | Delete existing scan succeeds | `DELETE /api/v1/scans/{scan_id}` | HTTP 200 or 204 |
| IT-047 | `test_delete_nonexistent_scan_returns_404` | Delete unknown scan_id returns 404 | `DELETE /api/v1/scans/nonexistent` | HTTP 404 |

---

### 2.3 Benchmark API — `test_benchmark_api.py`

| Test ID | Function | Description | Request | Expected |
|---------|----------|-------------|---------|----------|
| IT-048 | `test_list_returns_200` | List test cases returns 200 | `GET /api/v1/benchmark/test-cases` | HTTP 200 |
| IT-049 | `test_list_returns_array` | List response is an array | `GET /api/v1/benchmark/test-cases` | `isinstance(body, list)` |
| IT-050 | `test_list_count_matches_seeded` | Count matches seeded test cases | `GET /api/v1/benchmark/test-cases` | `len(body) == seeded_count` |
| IT-051 | `test_filter_by_cwe` | CWE filter narrows results | `GET /api/v1/benchmark/test-cases?cwe=CWE-89` | only CWE-89 cases |
| IT-052 | `test_filter_by_language_python` | Language filter narrows results | `GET /api/v1/benchmark/test-cases?language=python` | only python cases |
| IT-053 | `test_filter_by_label_vulnerable` | Label filter narrows results | `GET /api/v1/benchmark/test-cases?label=vulnerable` | only vulnerable cases |
| IT-054 | `test_non_admin_can_list` | Normal user can list test cases | `GET /api/v1/benchmark/test-cases` (normal token) | HTTP 200 |
| IT-055 | `test_empty_db_returns_empty_list` | No test cases -> empty array | `GET /api/v1/benchmark/test-cases` (empty DB) | `body == []` |
| IT-056 | `test_admin_can_create_test_case` | Admin creates a test case | `POST /api/v1/benchmark/test-cases` (admin) | HTTP 200 or 201 |
| IT-057 | `test_created_case_has_id` | Created case response includes id | `POST /api/v1/benchmark/test-cases` | `id` key present |
| IT-058 | `test_missing_required_field_returns_422` | Missing required field rejected | `POST /api/v1/benchmark/test-cases` (incomplete) | HTTP 422 |
| IT-059 | `test_invalid_label_returns_422` | Label must be vulnerable or safe | `POST /api/v1/benchmark/test-cases` (label="bad") | HTTP 422 |
| IT-060 | `test_run_with_no_test_cases_returns_empty_run` | Run with empty DB returns zero metrics | `POST /api/v1/benchmark/runs` (empty DB) | `total == 0` |
| IT-061 | `test_run_returns_metrics_fields` | Run response has tp, fp, fn, precision, recall, f1 | `POST /api/v1/benchmark/runs` | all metric keys present |
| IT-062 | `test_run_precision_between_0_and_1` | Precision in valid range | `POST /api/v1/benchmark/runs` | `0 <= precision <= 1` |
| IT-063 | `test_run_f1_between_0_and_1` | F1 in valid range | `POST /api/v1/benchmark/runs` | `0 <= f1 <= 1` |
| IT-064 | `test_run_stored_and_retrievable` | Run is persisted and retrievable | `POST /api/v1/benchmark/runs`, then list | run_id appears in list |
| IT-065 | `test_exploit_not_called_during_benchmark` | LLM exploit path suppressed during run | `POST /api/v1/benchmark/runs` | `enable_exploit == False` captured |
| IT-066 | `test_leaderboard_returns_200` | Leaderboard endpoint returns 200 | `GET /api/v1/benchmark/leaderboard` | HTTP 200 |
| IT-067 | `test_leaderboard_returns_list` | Leaderboard response is an array | `GET /api/v1/benchmark/leaderboard` | `isinstance(body, list)` |
| IT-068 | `test_leaderboard_sorted_by_best_f1_desc` | Entries sorted by best F1 descending | `GET /api/v1/benchmark/leaderboard` (3 runs) | f1s strictly descending |
| IT-069 | `test_leaderboard_entries_have_required_keys` | Each entry has model_used, best_f1, trend | `GET /api/v1/benchmark/leaderboard` | all keys present |
| IT-070 | `test_list_runs_returns_200` | List runs returns 200 | `GET /api/v1/benchmark/runs` | HTTP 200 |
| IT-071 | `test_list_runs_returns_list` | List runs response is an array | `GET /api/v1/benchmark/runs` | `isinstance(body, list)` |

---

### 2.4 Kill Chain API — `test_kill_chain_api.py`

| Test ID | Function | Description | Request | Expected |
|---------|----------|-------------|---------|----------|
| IT-072 | `test_returns_200_for_existing_scan` | Kill chain for existing scan returns 200 | `GET /api/v1/kill-chain/{scan_id}` | HTTP 200 |
| IT-073 | `test_returns_404_for_missing_scan` | Kill chain for unknown scan returns 404 | `GET /api/v1/kill-chain/nonexistent` | HTTP 404 |
| IT-074 | `test_response_has_required_top_level_keys` | Response has scan_id, stages, kill_chains, blast_radius, narrative | `GET /api/v1/kill-chain/{scan_id}` | all top-level keys present |
| IT-075 | `test_stages_count_is_always_8` | Always 8 MITRE ATT&CK stages | `GET /api/v1/kill-chain/{scan_id}` | `len(stages) == 8` |
| IT-076 | `test_each_stage_has_required_fields` | Each stage has id, name, vulns, description | `GET /api/v1/kill-chain/{scan_id}` | all fields present in each stage |
| IT-077 | `test_scan_id_echoed_in_response` | Response scan_id matches requested scan_id | `GET /api/v1/kill-chain/{scan_id}` | `response.scan_id == scan_id` |
| IT-078 | `test_unauthenticated_returns_401` | Kill chain without token returns 401 | `GET /api/v1/kill-chain/{scan_id}` (no token) | HTTP 401 |
| IT-079 | `test_sql_injection_mapped_to_initial_access` | SQLi vuln appears in initial_access stage | scan with SQL Injection | initial_access stage vulns > 0 |
| IT-080 | `test_command_injection_mapped_to_execution` | Command Injection vuln in execution stage | scan with Command Injection | execution stage vulns > 0 |
| IT-081 | `test_xss_mapped_to_exfiltration` | XSS vuln in exfiltration stage | scan with XSS | exfiltration stage vulns > 0 |
| IT-082 | `test_hardcoded_secret_mapped_to_credential_access` | Hardcoded Secret in credential_access stage | scan with Hardcoded Secret | credential_access stage vulns > 0 |
| IT-083 | `test_inactive_stages_have_zero_vuln_count` | Stages without matched vulns report 0 | scan with only SQLi | non-initial_access stages vuln_count == 0 |
| IT-084 | `test_empty_scan_has_zero_blast_radius` | Scan with no vulns -> blast_radius 0 | scan with empty vulnerabilities | `blast_radius == 0` |
| IT-085 | `test_blast_radius_is_integer` | blast_radius is an integer | `GET /api/v1/kill-chain/{scan_id}` | `isinstance(blast_radius, int)` |
| IT-086 | `test_blast_radius_between_0_and_100` | blast_radius in [0, 100] | `GET /api/v1/kill-chain/{scan_id}` | `0 <= blast_radius <= 100` |
| IT-087 | `test_multi_vuln_higher_radius_than_single` | More vulns -> higher blast radius | scan with 3 vulns vs 1 | radius_3 > radius_1 |
| IT-088 | `test_no_vulns_returns_empty_kill_chains` | No vulns -> empty kill_chains list | scan with empty vulnerabilities | `kill_chains == []` |
| IT-089 | `test_multi_stage_vulns_produce_kill_chains` | Vulns in 2+ stages produce at least one chain | scan with SQLi + Command Injection | `len(kill_chains) >= 1` |
| IT-090 | `test_chains_capped_at_4` | At most 4 kill chains returned | scan with 8 staged vulns | `len(kill_chains) <= 4` |
| IT-091 | `test_chain_probability_between_0_and_1` | Each chain probability in [0, 1] | any scan with chains | `0 <= p <= 1` for all chains |
| IT-092 | `test_stats_total_vulns_matches` | stats.total_vulns matches seeded count | scan with 3 vulns | `total_vulns == 3` |
| IT-093 | `test_stats_stages_hit_is_positive_when_vulns_exist` | stages_hit > 0 when vulns present | scan with vulns | `stages_hit > 0` |
| IT-094 | `test_stats_zero_for_empty_scan` | stats all zero for empty scan | scan with 0 vulns | `total_vulns == 0, stages_hit == 0` |

---

### 2.5 Repositories API — `test_repositories_api.py`

| Test ID | Function | Description | Request | Expected |
|---------|----------|-------------|---------|----------|
| IT-095 | `test_list_repos_returns_200` | List repos returns 200 | `GET /api/v1/repositories/` | HTTP 200 |
| IT-096 | `test_list_repos_returns_list` | List repos response is array | `GET /api/v1/repositories/` | `isinstance(body, list)` |
| IT-097 | `test_user_only_sees_own_repos` | User sees only their own repos | `GET /api/v1/repositories/` | repos belong to auth user |
| IT-098 | `test_unauthenticated_returns_401` | No token -> 401 | `GET /api/v1/repositories/` (no token) | HTTP 401 |
| IT-099 | `test_create_repo_returns_201_or_200` | Create repo succeeds | `POST /api/v1/repositories/` | HTTP 200 or 201 |
| IT-100 | `test_create_repo_missing_name_returns_422` | Missing name field rejected | `POST /api/v1/repositories/` (no name) | HTTP 422 |
| IT-101 | `test_create_repo_missing_url_returns_422` | Missing url field rejected | `POST /api/v1/repositories/` (no url) | HTTP 422 |
| IT-102 | `test_get_nonexistent_repo_returns_404` | Unknown repo ID returns 404 | `GET /api/v1/repositories/{id}` (unknown) | HTTP 404 |
| IT-103 | `test_get_existing_repo_returns_200` | Known repo returns 200 | `GET /api/v1/repositories/{id}` | HTTP 200 |
| IT-104 | `test_get_repo_returns_name` | Repo response includes name field | `GET /api/v1/repositories/{id}` | `name` key in response |
| IT-105 | `test_delete_nonexistent_repo_returns_404` | Delete unknown repo returns 404 | `DELETE /api/v1/repositories/{id}` (unknown) | HTTP 404 |
| IT-106 | `test_delete_own_repo_returns_200_or_204` | Delete own repo succeeds | `DELETE /api/v1/repositories/{id}` | HTTP 200 or 204 |
| IT-107 | `test_deleted_repo_no_longer_retrievable` | After delete, repo returns 404 | `DELETE` then `GET` same ID | second request HTTP 404 |

---

## 3. Functional Tests

**File:** `tests/functional/test_scan_workflow.py`

| Test ID | Function | Description | Workflow | Expected |
|---------|----------|-------------|----------|----------|
| FT-001 | `test_register_and_login_produces_token` | Full register -> login returns JWT | `POST /register` -> `POST /login` | `access_token` present |
| FT-002 | `test_full_scan_workflow` | Register -> login -> scan with token | three-step sequence | scan returns 200, scan_id present |
| FT-003 | `test_token_required_to_scan` | Scanning without auth token is rejected | `POST /scan/scan` (no token) | HTTP 401 |
| FT-004 | `test_me_endpoint_returns_registered_user` | /me after register+login returns the same user | register -> login -> `GET /auth/me` | email matches registered email |
| FT-005 | `test_scan_result_feeds_kill_chain` | Scan vulns appear in kill chain | scan with 3 vulns -> kill chain | `total_vulns == 3, 8 stages` |
| FT-006 | `test_high_severity_scan_has_high_blast_radius` | Critical-severity scan has high blast radius | critical vuln scan -> kill chain | `blast_radius > 50` |
| FT-007 | `test_completed_scan_has_sarif_report` | SARIF export accessible for completed scan | `GET /api/v1/scans/{scan_id}/sarif` | HTTP 200, 404, or 500 |
| FT-008 | `test_completed_scan_has_csv_report` | CSV export accessible for completed scan | `GET /api/v1/scans/{scan_id}/csv` | HTTP 200, 404, or 500 |
| FT-009 | `test_nonexistent_scan_report_returns_404` | Report for unknown scan returns 404 | `GET /api/v1/scans/nonexistent/sarif` | HTTP 404 |
| FT-010 | `test_dashboard_summary_returns_200` | Dashboard summary accessible | `GET /api/v1/dashboard/summary` | HTTP 200 |
| FT-011 | `test_dashboard_summary_has_expected_keys` | Dashboard summary is a dict | `GET /api/v1/dashboard/summary` | `isinstance(body, dict)` |
| FT-012 | `test_recent_scans_returns_200` | Recent scans list accessible | `GET /api/v1/dashboard/recent-scans` | HTTP 200 |

---

## 4. Business Rule Tests

### 4.1 Role-Based Access Control — `test_role_access.py`

| Test ID | Function | Description | Setup | Expected |
|---------|----------|-------------|-------|----------|
| BR-001 | `test_all_protected_endpoints_return_401_without_token` | 7 protected endpoints all reject unauthenticated requests | no token, bare client | all return HTTP 401 |
| BR-002 | `test_normal_cannot_access_admin_user_list` | Normal user blocked from admin user list | normal token | HTTP 403 or 404 |
| BR-003 | `test_normal_cannot_update_user_roles` | Normal user cannot modify roles | normal token + PATCH | HTTP 403 or 404 |
| BR-004 | `test_normal_can_access_own_profile` | Normal user can get their own /me | normal token | HTTP 200, `role == "normal"` |
| BR-005 | `test_normal_can_view_scan_list` | Normal user can list scans | normal token | HTTP 200 |
| BR-006 | `test_normal_can_view_dashboard` | Normal user can access dashboard | normal token | HTTP 200 |
| BR-007 | `test_normal_can_view_attack_surface` | Normal user can view attack surface | normal token + sample_scan | HTTP 200 or 404 |
| BR-008 | `test_normal_can_view_kill_chain` | Normal user can access kill chain | normal token + sample_scan | HTTP 200 |
| BR-009 | `test_normal_cannot_run_sandbox` | Sandbox may be restricted by role | normal token | HTTP 200, 403, 422, or 500 |
| BR-010 | `test_admin_can_list_all_users` | Admin can access user management | admin token | HTTP 200 |
| BR-011 | `test_admin_user_list_returns_list` | Admin user list is an array | admin token | `isinstance(body, list)` |
| BR-012 | `test_admin_can_view_benchmark` | Admin can list benchmark test cases | admin token | HTTP 200 |
| BR-013 | `test_admin_can_run_benchmark` | Admin can trigger benchmark run | admin token + mock LLM | HTTP 200 or 201 |
| BR-014 | `test_admin_can_access_leaderboard` | Admin can view benchmark leaderboard | admin token | HTTP 200 |
| BR-015 | `test_admin_can_view_own_profile` | Admin's /me returns admin role | admin token | HTTP 200, `role == "admin"` |
| BR-016 | `test_premium_can_access_patches_endpoint` | Premium user reaches patches endpoint (auth passes) | premium token | HTTP 200 or 404 |
| BR-017 | `test_premium_can_view_repositories` | Premium user can list repositories | premium token | HTTP 200 |
| BR-018 | `test_premium_can_view_kill_chain` | Premium user can access kill chain | premium token + seeded scan | HTTP 200 |
| BR-019 | `test_premium_cannot_access_admin_panel` | Premium user blocked from admin panel | premium token | HTTP 403 or 404 |
| BR-020 | `test_normal_user_cannot_self_promote_to_admin` | User cannot change own role to admin | normal token + own uid | HTTP 403 or 404 |
| BR-021 | `test_normal_user_cannot_promote_other_user` | User cannot change another user's role | normal token + other uid | HTTP 403 or 404 |
| BR-022 | `test_jwt_role_claim_does_not_bypass_db_role_check` | Forged admin JWT claim rejected if DB says normal | forged token with `role:admin`, DB has `role:normal` | HTTP 401, 403, or 200 (server checks DB) |

---

### 4.2 Vulnerability Detection — `test_vulnerability_detection.py`

> Each row is one parametrized test instance expanded from `@pytest.mark.parametrize`.  
> `VULN` = must fire. `SAFE` = must not fire.

#### Path Traversal — RULE: `PATH_TRAVERSAL`

| Test ID | Code Sample | Direction | Expected |
|---------|-------------|-----------|----------|
| BR-023 | `open("/uploads/" + filename)` | VULN | detected |
| BR-024 | `open(user_file, "r")` | VULN | detected |
| BR-025 | `os.path.join(BASE, request.args.get('f'))` | VULN | detected |
| BR-026 | `send_file(request.args.get('name'))` | VULN | detected |
| BR-027 | `res.sendFile(req.query.file)` | VULN | detected |
| BR-028 | `path.join(__dirname, req.params.name)` | VULN | detected |
| BR-029 | `open("/var/app/config.json", "r")` | SAFE | not detected |
| BR-030 | `send_file("/static/logo.png")` | SAFE | not detected |
| BR-031 | `os.path.join('/static', 'logo.png')` | SAFE | not detected |

#### Weak Cryptography — RULE: `WEAK_CRYPTO`

| Test ID | Code Sample | Direction | Expected |
|---------|-------------|-----------|----------|
| BR-032 | `hashlib.md5(data.encode()).hexdigest()` | VULN | detected |
| BR-033 | `hashlib.sha1(password)` | VULN | detected |
| BR-034 | `crypto.createHash('md5')` | VULN | detected |
| BR-035 | `crypto.createHash('sha1')` | VULN | detected |
| BR-036 | `RSA.generate(1024)` | VULN | detected |
| BR-037 | `RSA.generate(512)` | VULN | detected |
| BR-038 | `key_size=1024` | VULN | detected |
| BR-039 | `hashlib.sha256(data)` | SAFE | not detected |
| BR-040 | `hashlib.sha512(data)` | SAFE | not detected |
| BR-041 | `crypto.createHash('sha256')` | SAFE | not detected |
| BR-042 | `RSA.generate(4096)` | SAFE | not detected |
| BR-043 | `key_size=2048` | SAFE | not detected |

#### Hardcoded Secrets — RULE: `HARDCODED_SECRETS`

| Test ID | Code Sample | Direction | Expected |
|---------|-------------|-----------|----------|
| BR-044 | `JWT_SECRET = "my-hardcoded-secret"` | VULN | detected |
| BR-045 | `api_key = "sk-1234567890abcdef"` | VULN | detected |
| BR-046 | `app.secret_key = "hardcoded-flask-secret"` | VULN | detected |
| BR-047 | `password = "admin123"` | VULN | detected |
| BR-048 | `secret = os.environ.get("JWT_SECRET")` | SAFE | not detected |
| BR-049 | `key = os.getenv("API_KEY", "")` | SAFE | not detected |
| BR-050 | `password = config.get("db_password")` | SAFE | not detected |

#### Command Injection — RULE: `COMMAND_INJECTION`

| Test ID | Code Sample | Direction | Expected |
|---------|-------------|-----------|----------|
| BR-051 | `os.system(user_cmd)` | VULN | detected |
| BR-052 | `os.popen(cmd)` | VULN | detected |
| BR-053 | `subprocess.run(cmd, shell=True)` | VULN | detected |
| BR-054 | `child_process.exec(req.body.cmd)` | VULN | detected |
| BR-055 | `child_process.execSync(userInput)` | VULN | detected |
| BR-056 | `subprocess.run(['ls', '-la'])` | SAFE | not detected |
| BR-057 | `subprocess.run(['git', 'status'], check=True)` | SAFE | not detected |
| BR-058 | `subprocess.Popen(['python', script])` | SAFE | not detected |

#### Insecure Deserialization — RULE: `INSECURE_DESERIALIZATION`

| Test ID | Code Sample | Direction | Expected |
|---------|-------------|-----------|----------|
| BR-059 | `pickle.loads(data)` | VULN | detected |
| BR-060 | `pickle.load(f)` | VULN | detected |
| BR-061 | `yaml.load(stream)` | VULN | detected |
| BR-062 | `yaml.unsafe_load(data)` | VULN | detected |
| BR-063 | `marshal.loads(raw)` | VULN | detected |
| BR-064 | `jsonpickle.decode(payload)` | VULN | detected |
| BR-065 | `yaml.safe_load(data)` | SAFE | not detected |
| BR-066 | `yaml.load(data, Loader=SafeLoader)` | SAFE | not detected |
| BR-067 | `json.loads(body)` | SAFE | not detected |
| BR-068 | `JSON.parse(body)` | SAFE | not detected |

#### Debug Mode / Information Exposure — RULE: `INFORMATION_EXPOSURE_ERROR`

| Test ID | Code Sample | Direction | Expected |
|---------|-------------|-----------|----------|
| BR-069 | `app.run(debug=True)` | VULN | detected |
| BR-070 | `app.run(host='0.0.0.0', debug=True)` | VULN | detected |
| BR-071 | `DEBUG = True` | VULN | detected |
| BR-072 | `app.run(debug=False)` | SAFE | not detected |
| BR-073 | `app.run(host='0.0.0.0', port=8080)` | SAFE | not detected |
| BR-074 | `DEBUG = False` | SAFE | not detected |
| BR-075 | `debug = os.environ.get('DEBUG', 'false')` | SAFE | not detected |

#### Insecure Cookie — RULE: `INSECURE_COOKIE`

| Test ID | Code Sample | Direction | Expected |
|---------|-------------|-----------|----------|
| BR-076 | `set_cookie('session', token)` | VULN | detected |
| BR-077 | `set_cookie('auth', value, httponly=False)` | VULN | detected |
| BR-078 | `res.cookie('session', token)` | VULN | detected |
| BR-079 | `set_cookie('session', token, secure=True)` | SAFE | not detected |
| BR-080 | `res.cookie('auth', value, { secure: true, httpOnly: true })` | SAFE | not detected |

#### SSRF — RULE: `SSRF`

| Test ID | Code Sample | Direction | Expected |
|---------|-------------|-----------|----------|
| BR-081 | `requests.get(request.args.get('url'))` | VULN | detected |
| BR-082 | `requests.post(req.body.target)` | VULN | detected |
| BR-083 | `urllib.request.urlopen(req.query.url)` | VULN | detected |
| BR-084 | `httpx.get(request.json().get('url'))` | VULN | detected |
| BR-085 | `requests.get("https://api.example.com/data")` | SAFE | not detected |
| BR-086 | `requests.get(INTERNAL_API_URL)` | SAFE | not detected |
| BR-087 | `urllib.request.urlopen("https://fixed.url")` | SAFE | not detected |

#### Unvalidated Redirect — RULE: `UNVALIDATED_REDIRECT`

| Test ID | Code Sample | Direction | Expected |
|---------|-------------|-----------|----------|
| BR-088 | `res.redirect(req.query.next)` | VULN | detected |
| BR-089 | `res.redirect(req.params.url)` | VULN | detected |
| BR-090 | `redirect(request.args.get('url'))` | VULN | detected |
| BR-091 | `redirect(request.form.get('next'))` | VULN | detected |
| BR-092 | `res.redirect("/dashboard")` | SAFE | not detected |
| BR-093 | `redirect("/home")` | SAFE | not detected |

---

### 4.3 Benchmark Scoring — `test_benchmark_scoring.py`

#### Metrics Formula — `TestMetricsFormula`

| Test ID | Function | Description | Input (tp, fp, fn, tn) | Expected |
|---------|----------|-------------|------------------------|----------|
| BR-094 | `test_perfect_precision` | All TP, no FP -> precision = 1.0 | (10, 0, 5, 5) | `precision == 1.0` |
| BR-095 | `test_perfect_recall` | All TP, no FN -> recall = 1.0 | (10, 5, 0, 5) | `recall == 1.0` |
| BR-096 | `test_f1_zero_when_precision_zero` | No TP + some FP -> F1 = 0 | (0, 10, 5, 5) | `f1 == 0.0` |
| BR-097 | `test_f1_zero_when_recall_zero` | No TP + no FP but FN -> F1 = 0 | (0, 0, 10, 5) | `f1 == 0.0` |
| BR-098 | `test_precision_recall_both_50pct_gives_f1_50pct` | p=0.5, r=0.5 -> F1=0.5 | (5, 5, 5, 5) | `p==r==f1==0.5` |
| BR-099 | `test_high_precision_low_recall_f1_bounded` | p>0.8, r<0.2 -> F1<0.2 | (9, 1, 81, 9) | `p>0.8, r<0.2, f1<0.2` |
| BR-100 | `test_fp_rate_zero_when_no_negatives` | No TN -> FP rate = 0.0 | (10, 0, 5, 0) | `fpr == 0.0` |
| BR-101 | `test_fp_rate_one_when_all_negatives_are_fp` | All negatives are FP -> fpr = 1.0 | (5, 10, 5, 0) | `fpr == 1.0` |

#### Outcome Counting — `TestOutcomeCounting`

| Test ID | Function | Label | Detected | Expected |
|---------|----------|-------|----------|----------|
| BR-102 | `test_outcome_classification[vulnerable-True-TP]` | vulnerable | True | TP |
| BR-103 | `test_outcome_classification[vulnerable-False-FN]` | vulnerable | False | FN |
| BR-104 | `test_outcome_classification[safe-True-FP]` | safe | True | FP |
| BR-105 | `test_outcome_classification[safe-False-TN]` | safe | False | TN |
| BR-106 | `test_all_correct_detections_all_tp_or_tn` | 2 vuln detected + 2 safe not detected | — | TP=2, TN=2, FP=0, FN=0 |
| BR-107 | `test_all_false_positives_scenario` | 5 safe cases all detected | — | all 5 outcomes == FP |
| BR-108 | `test_mixed_outcomes_counted_correctly` | TP, FN, FP, TN, TP | — | TP=2, FN=1, FP=1, TN=1 |

#### CWE Bucketing — `TestCWEBucketing`

| Test ID | Function | Description | Expected |
|---------|----------|-------------|----------|
| BR-109 | `test_per_cwe_metrics_computed` | CWE-89 has precision=1.0; CWE-79 has precision=0.0 | per-CWE metrics computed correctly |
| BR-110 | `test_cwe_with_only_tp_has_perfect_precision` | 5 TPs, 0 FPs -> precision=1.0, recall=5/7 | `p==1.0, r~0.714` |
| BR-111 | `test_cwe_with_only_fp_has_zero_precision` | 0 TPs, 5 FPs -> precision=0.0, F1=0.0 | `p==0.0, f1==0.0` |

#### BenchmarkService Integration — `TestBenchmarkServiceRun`

| Test ID | Function | Description | Setup | Expected |
|---------|----------|-------------|-------|----------|
| BR-112 | `test_empty_test_cases_returns_empty_run` | No test cases -> zero-metric run | empty DB | `total==0, tp==0, fp==0` |
| BR-113 | `test_all_detected_vulnerable_all_tp` | 3 vulnerable, pipeline detects all | 3 vuln cases, mock detects=True | `tp==3, fp==0, fn==0, precision==1.0, recall==1.0` |
| BR-114 | `test_none_detected_all_fn` | 3 vulnerable, pipeline misses all | 3 vuln cases, mock detects=False | `fn==3, tp==0, recall==0.0` |
| BR-115 | `test_false_positives_on_safe_code` | 4 safe cases, pipeline fires on all | 4 safe cases, mock detects=True | `fp==4, tp==0, precision==0.0` |
| BR-116 | `test_run_saved_to_database` | Run result persisted with an ID | 1 vuln case, detect=True | `run.id is not None`, found in DB |
| BR-117 | `test_run_type_is_synthetic` | run_type is always "synthetic" | any test cases | `run.run_type == "synthetic"` |
| BR-118 | `test_model_used_is_static_only_when_llm_disabled` | model_used is "static-only" when LLM disabled | `enable_llm=False` | `run.model_used == "static-only"` |
| BR-119 | `test_exploit_disabled_during_benchmark` | PipelineConfig has enable_exploit=False | captures config via side_effect | `captured["enable_exploit"] is False` |

#### Leaderboard — `TestLeaderboard`

| Test ID | Function | Description | Setup | Expected |
|---------|----------|-------------|-------|----------|
| BR-120 | `test_leaderboard_sorted_by_best_f1_desc` | Entries sorted by best F1 descending | 3 runs: f1=0.9, 0.5, 0.75 | order: 0.9, 0.75, 0.5 |
| BR-121 | `test_leaderboard_empty_when_no_runs` | No runs -> empty leaderboard | empty DB | `entries == []` |
| BR-122 | `test_leaderboard_trend_up_when_improving` | Later run better -> trend arrow up | f1=0.8 today, f1=0.7 yesterday | `model_x.trend == "up arrow"` |
| BR-123 | `test_leaderboard_trend_down_when_degrading` | Later run worse -> trend arrow down | f1=0.6 today, f1=0.75 yesterday | `model_y.trend == "down arrow"` |

---

## 5. Summary

| Category | Files | Test Functions | Parametrized Instances |
|----------|-------|---------------|----------------------|
| Unit Tests | 13 files | 168 | 168 |
| Integration Tests | 5 files | 107 | 107 |
| Functional Tests | 1 file | 12 | 12 |
| Business Rule Tests | 3 files | 67 | 123 |
| **Total** | **22 files** | **354** | **~420** |

### Coverage by Feature Area

| Feature Area | Test IDs |
|-------------|----------|
| Authentication & JWT | UT-001 to UT-023, IT-001 to IT-029, FT-001 to FT-004 |
| Benchmark Metrics Engine | UT-024 to UT-038, BR-094 to BR-123, IT-048 to IT-071 |
| Kill Chain / ATT&CK Mapping | UT-039 to UT-077, IT-072 to IT-094, FT-005 to FT-006 |
| Vulnerability Pattern Detection | UT-078 to UT-123, BR-023 to BR-093 |
| Static AST / DFG Analysis | UT-124 to UT-133 |
| Patch Generation Pipeline | UT-134 to UT-168 |
| Scan API | IT-030 to IT-047, FT-002 to FT-003, FT-007 to FT-009 |
| Repositories API | IT-095 to IT-107 |
| Dashboard | FT-010 to FT-012 |
| RBAC / Authorization | BR-001 to BR-022 |

---

## 6. How to Run

```bash
# All tests
pytest tests/ -v

# By category
pytest tests/unit/ -v
pytest tests/integration/ -v
pytest tests/functional/ -v
pytest tests/business_rules/ -v

# Single file
pytest tests/unit/test_security.py -v
pytest tests/unit/test_kill_chain_logic.py -v
pytest tests/unit/test_query_patterns.py -v
pytest tests/business_rules/test_vulnerability_detection.py -v
pytest tests/business_rules/test_benchmark_scoring.py -v
pytest tests/patch_module/ -v

# Legacy AST / DFG tests
pytest tests/test_js_flows.py tests/test_cross_file_flow.py tests/test_reexport_chain.py -v

# Filter by keyword
pytest tests/ -k "kill_chain" -v
pytest tests/ -k "sqli or sql_injection" -v
pytest tests/ -k "admin" -v
pytest tests/ -k "benchmark" -v
```

### Test Infrastructure

| Component | Implementation |
|-----------|---------------|
| In-memory MongoDB | `mongomock.MongoClient()` (session-scoped fixture) |
| HTTP test client | `fastapi.testclient.TestClient` |
| Auth dependency override | `app.dependency_overrides[get_current_user]` |
| DB dependency override | `app.dependency_overrides[get_mongo_db]` |
| LLM mocking | `unittest.mock.patch("semantic_engine.pipeline.get_pipeline")` |
| Async test support | `pytest-asyncio` with `asyncio_mode = auto` |
| Password hashing | `bcrypt` via `app.core.security.hash_password` |
| JWT creation | `python-jose` via `app.core.security.create_access_token` |
| Fake LLM DB | `tests/patch_module/_fake_db.FakeDB` |
| Pattern matching helper | `fires(rule_id, code)` using `queries/queries.json` |
