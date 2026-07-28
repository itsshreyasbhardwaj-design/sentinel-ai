import type { Rule } from '../types.js';
import {
  all,
  contextMatches,
  hasDynamicInterpolation,
  notInComment,
  notInTests,
} from './engine.js';

/**
 * Native SAST rule pack.
 *
 * Rules are tuned for *precision over recall*: a security tool that cries wolf
 * gets muted, and a muted tool finds nothing. Where a pattern alone cannot tell
 * a real defect from a safe idiom, the rule carries a `validate` callback (most
 * often "is any part of this expression dynamic?") rather than being shipped
 * noisy.
 */

const REF = {
  cwe: (id: number) => `https://cwe.mitre.org/data/definitions/${id}.html`,
  owasp: (slug: string) => `https://owasp.org/Top10/${slug}/`,
};

/* ------------------------------------------------------------------ */
/* JavaScript / TypeScript                                             */
/* ------------------------------------------------------------------ */

const jsRules: Rule[] = [
  {
    id: 'js-sql-injection',
    title: 'SQL query built by string concatenation',
    description:
      'A SQL statement is assembled from a template literal or concatenation that includes a variable. Any value that reaches this expression can alter the query structure.',
    severity: 'critical',
    kind: 'sast',
    confidence: 'medium',
    languages: ['javascript', 'typescript'],
    patterns: [
      /\b(?:query|execute|raw|exec)\s*\(\s*[`'"][^`'"]*\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\b/i,
      /\b(?:sequelize|knex|db|connection|pool|client)\s*\.\s*(?:query|raw)\s*\(\s*[`'"]/i,
      // The very common shape where the statement is built into a variable
      // first and executed on a later line.
      /(?:const|let|var)\s+\w*(?:query|sql|statement|stmt)\w*\s*=\s*[`'"][^`'"]*\b(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b/i,
    ],
    excludePatterns: [/\?\s*[,)]/, /\$\d+/],
    validate: all(notInComment, notInTests, (m) => hasDynamicInterpolation(m.line)),
    taxonomy: {
      cwe: ['CWE-89'],
      owaspTop10: ['A03:2021-Injection'],
      references: [
        { title: 'CWE-89: SQL Injection', url: REF.cwe(89) },
        { title: 'OWASP A03:2021 Injection', url: REF.owasp('A03_2021-Injection') },
      ],
    },
    remediationHint:
      'Use parameterized queries (`db.query("SELECT * FROM users WHERE id = $1", [id])`) or an ORM query builder.',
  },
  {
    id: 'js-command-injection',
    title: 'Shell command built from dynamic input',
    description:
      '`exec`/`execSync` spawn a shell, so any interpolated value can inject additional commands via `;`, `&&` or backticks.',
    severity: 'critical',
    kind: 'sast',
    confidence: 'high',
    languages: ['javascript', 'typescript'],
    patterns: [
      /\b(?:child_process\.)?exec(?:Sync)?\s*\(\s*[`'"][^`'"]*\$\{/,
      /\b(?:child_process\.)?exec(?:Sync)?\s*\(\s*[^,)]*\+/,
      /\bshelljs?\.\s*exec\s*\(/,
    ],
    validate: all(notInComment, notInTests),
    taxonomy: {
      cwe: ['CWE-78'],
      owaspTop10: ['A03:2021-Injection'],
      references: [{ title: 'CWE-78: OS Command Injection', url: REF.cwe(78) }],
    },
    remediationHint:
      'Use `execFile`/`spawn` with an argument array so no shell is involved: `execFile("git", ["clone", url])`.',
  },
  {
    id: 'js-code-injection-eval',
    title: 'Dynamic code execution via eval or Function constructor',
    description:
      'Evaluating a string as code turns any attacker-controlled value into arbitrary code execution in the application context.',
    severity: 'critical',
    kind: 'sast',
    confidence: 'high',
    languages: ['javascript', 'typescript'],
    patterns: [
      /\beval\s*\(/,
      /\bnew\s+Function\s*\(/,
      /\bsetTimeout\s*\(\s*["'`][^"'`]+["'`]\s*,/,
      /\bvm\.runInThisContext\s*\(/,
    ],
    excludePatterns: [/\/\/\s*safe/i],
    validate: all(notInComment, notInTests),
    taxonomy: {
      cwe: ['CWE-94', 'CWE-95'],
      owaspTop10: ['A03:2021-Injection'],
      references: [{ title: 'CWE-94: Code Injection', url: REF.cwe(94) }],
    },
    remediationHint: 'Replace `eval` with `JSON.parse` for data, or a lookup table for dispatch.',
  },
  {
    id: 'js-xss-dangerous-html',
    title: 'Unsanitized value rendered as HTML',
    description:
      'Assigning to `innerHTML` or using `dangerouslySetInnerHTML` with a dynamic value lets attacker-supplied markup execute in the victim browser.',
    severity: 'high',
    kind: 'sast',
    confidence: 'medium',
    languages: ['javascript', 'typescript'],
    patterns: [
      /\.innerHTML\s*=\s*(?!['"`]\s*['"`])/,
      /dangerouslySetInnerHTML\s*=\s*\{\{/,
      /\.outerHTML\s*=\s*/,
      /document\.write(?:ln)?\s*\(/,
      /\$\([^)]*\)\.html\s*\(\s*[^)'"`]/,
    ],
    excludePatterns: [/DOMPurify|sanitize(?:Html)?\s*\(/i],
    validate: all(notInComment, notInTests),
    taxonomy: {
      cwe: ['CWE-79'],
      owaspTop10: ['A03:2021-Injection'],
      references: [{ title: 'CWE-79: Cross-site Scripting', url: REF.cwe(79) }],
    },
    remediationHint:
      'Use `textContent` for text, or sanitize with DOMPurify before assigning HTML.',
  },
  {
    id: 'js-ssrf-fetch',
    title: 'Outbound request to a dynamically constructed URL',
    description:
      'When the destination of a server-side request is user-controlled, an attacker can reach internal services, cloud metadata endpoints, or localhost.',
    severity: 'high',
    kind: 'sast',
    confidence: 'low',
    languages: ['javascript', 'typescript'],
    patterns: [
      /\b(?:fetch|axios(?:\.get|\.post|\.put|\.delete)?|got|superagent\.get|request)\s*\(\s*(?:`[^`]*\$\{|[A-Za-z_$][\w$]*\s*[,)])/,
      /https?\.request\s*\(\s*[A-Za-z_$][\w$]*/,
    ],
    excludePatterns: [/["'`]https?:\/\/[a-z0-9.-]+["'`]\s*[,)]/i, /process\.env\./],
    validate: all(notInComment, notInTests, (m) =>
      /req\.|request\.|params|query|body|input|url/i.test(m.line),
    ),
    taxonomy: {
      cwe: ['CWE-918'],
      owaspTop10: ['A10:2021-Server-Side Request Forgery'],
      references: [{ title: 'CWE-918: SSRF', url: REF.cwe(918) }],
    },
    remediationHint:
      'Validate the URL against an allowlist of hosts and reject private/link-local address ranges before making the request.',
  },
  {
    id: 'js-path-traversal',
    title: 'Filesystem path built from untrusted input',
    description:
      'Joining user input into a filesystem path allows `../` sequences to escape the intended directory and read or write arbitrary files.',
    severity: 'high',
    kind: 'sast',
    confidence: 'medium',
    languages: ['javascript', 'typescript'],
    patterns: [
      /\bfs\.(?:readFile|writeFile|readFileSync|writeFileSync|createReadStream|unlink|rm)\s*\(\s*(?:path\.)?(?:join|resolve)?\s*\(?[^)]*(?:req\.|params|query|body|input)/,
      /\bpath\.join\s*\([^)]*(?:req\.|params\.|query\.|body\.)/,
    ],
    validate: all(notInComment, notInTests),
    taxonomy: {
      cwe: ['CWE-22'],
      owaspTop10: ['A01:2021-Broken Access Control'],
      references: [{ title: 'CWE-22: Path Traversal', url: REF.cwe(22) }],
    },
    remediationHint:
      'Resolve the path and verify it is still inside the intended root before touching the filesystem.',
  },
  {
    id: 'js-prototype-pollution',
    title: 'Recursive merge without prototype guards',
    description:
      'A deep merge that copies arbitrary keys can set `__proto__` or `constructor.prototype`, corrupting objects application-wide.',
    severity: 'high',
    kind: 'sast',
    confidence: 'low',
    languages: ['javascript', 'typescript'],
    patterns: [/for\s*\(\s*(?:const|let|var)\s+\w+\s+in\s+\w+\s*\)[^;]*\[\s*\w+\s*\]\s*=/],
    excludePatterns: [/hasOwnProperty|__proto__|Object\.create\(null\)/],
    validate: all(notInComment, notInTests),
    taxonomy: {
      cwe: ['CWE-1321'],
      references: [{ title: 'CWE-1321: Prototype Pollution', url: REF.cwe(1321) }],
    },
    remediationHint:
      'Reject `__proto__`, `constructor` and `prototype` keys, or use `structuredClone`/`Object.assign` on a null-prototype object.',
  },
  {
    id: 'js-insecure-deserialization',
    title: 'Deserialization of untrusted data',
    description:
      'Deserializers that reconstruct arbitrary types can be driven to instantiate gadget chains and execute code.',
    severity: 'high',
    kind: 'sast',
    confidence: 'medium',
    languages: ['javascript', 'typescript'],
    patterns: [/\bnode-serialize\b/, /\bunserialize\s*\(/, /\bjs-yaml\b[^;]*load\s*\(/],
    excludePatterns: [/safeLoad|yaml\.load\([^,)]*,\s*\{[^}]*schema/],
    validate: all(notInComment, notInTests),
    taxonomy: {
      cwe: ['CWE-502'],
      owaspTop10: ['A08:2021-Software and Data Integrity Failures'],
      references: [{ title: 'CWE-502: Deserialization of Untrusted Data', url: REF.cwe(502) }],
    },
    remediationHint: 'Use `JSON.parse`, or `yaml.load` with the safe schema.',
  },
  {
    id: 'js-tls-verification-disabled',
    title: 'TLS certificate verification disabled',
    description:
      'Disabling certificate validation makes every HTTPS connection trivially interceptable by any on-path attacker.',
    severity: 'critical',
    kind: 'sast',
    confidence: 'high',
    languages: ['javascript', 'typescript'],
    patterns: [
      /rejectUnauthorized\s*:\s*false/,
      /NODE_TLS_REJECT_UNAUTHORIZED\s*(?:=|\]\s*=)\s*['"]?0/,
      /strictSSL\s*:\s*false/,
      /checkServerIdentity\s*:\s*\(\s*\)\s*=>\s*(?:undefined|null|true)/,
    ],
    validate: notInComment,
    taxonomy: {
      cwe: ['CWE-295'],
      owaspTop10: ['A07:2021-Identification and Authentication Failures'],
      references: [{ title: 'CWE-295: Improper Certificate Validation', url: REF.cwe(295) }],
    },
    remediationHint:
      'Keep verification on and install the correct CA bundle. If a self-signed cert is needed, pin it via the `ca` option.',
  },
  {
    id: 'js-jwt-verification-bypass',
    title: 'JWT signature not verified',
    description:
      '`jwt.decode` reads the payload without checking the signature, so any client can forge claims. Accepting the `none` algorithm has the same effect.',
    severity: 'critical',
    kind: 'sast',
    confidence: 'high',
    languages: ['javascript', 'typescript'],
    patterns: [
      /\bjwt\.decode\s*\(/,
      /algorithms\s*:\s*\[\s*['"]none['"]/i,
      /\bverify\s*:\s*false/,
      /ignoreExpiration\s*:\s*true/,
    ],
    validate: all(notInComment, notInTests),
    taxonomy: {
      cwe: ['CWE-347', 'CWE-287'],
      owaspTop10: ['A07:2021-Identification and Authentication Failures'],
      references: [
        { title: 'CWE-347: Improper Verification of Cryptographic Signature', url: REF.cwe(347) },
      ],
    },
    remediationHint:
      'Use `jwt.verify(token, key, { algorithms: ["RS256"] })` and never trust `decode`.',
  },
  {
    id: 'js-weak-random-for-security',
    title: 'Math.random used for a security-sensitive value',
    description:
      '`Math.random` is a fast, predictable PRNG. Tokens, session ids, OTPs and password-reset codes derived from it are guessable.',
    severity: 'high',
    kind: 'sast',
    confidence: 'medium',
    languages: ['javascript', 'typescript'],
    patterns: [/Math\.random\s*\(\s*\)/],
    validate: all(
      notInComment,
      notInTests,
      contextMatches(/token|secret|password|key|nonce|salt|otp|session|csrf|reset|verif|auth/i),
    ),
    taxonomy: {
      cwe: ['CWE-338', 'CWE-330'],
      owaspTop10: ['A02:2021-Cryptographic Failures'],
      references: [{ title: 'CWE-338: Use of Cryptographically Weak PRNG', url: REF.cwe(338) }],
    },
    remediationHint: 'Use `crypto.randomUUID()` or `crypto.randomBytes(32).toString("hex")`.',
  },
  {
    id: 'js-cors-wildcard-credentials',
    title: 'CORS allows any origin together with credentials',
    description:
      'Reflecting an arbitrary origin while allowing credentials lets any website make authenticated requests on the user behalf.',
    severity: 'high',
    kind: 'sast',
    confidence: 'high',
    languages: ['javascript', 'typescript'],
    patterns: [
      /origin\s*:\s*(?:['"]\*['"]|true)\s*,[^}]*credentials\s*:\s*true/,
      /credentials\s*:\s*true\s*,[^}]*origin\s*:\s*(?:['"]\*['"]|true)/,
      /Access-Control-Allow-Origin['"]\s*,\s*['"]\*/,
    ],
    validate: notInComment,
    taxonomy: {
      cwe: ['CWE-942'],
      owaspTop10: ['A05:2021-Security Misconfiguration'],
      references: [{ title: 'CWE-942: Overly Permissive Cross-domain Policy', url: REF.cwe(942) }],
    },
    remediationHint: 'Echo only origins from an explicit allowlist when credentials are enabled.',
  },
  {
    id: 'js-insecure-cookie',
    title: 'Session cookie missing security attributes',
    description:
      'A cookie without `httpOnly` is readable by injected scripts; without `secure` it travels in cleartext; without `sameSite` it is available to cross-site requests.',
    severity: 'medium',
    kind: 'sast',
    confidence: 'medium',
    languages: ['javascript', 'typescript'],
    patterns: [/httpOnly\s*:\s*false/, /secure\s*:\s*false/, /sameSite\s*:\s*['"]none['"]/i],
    validate: all(notInComment, notInTests),
    taxonomy: {
      cwe: ['CWE-1004', 'CWE-614'],
      owaspTop10: ['A05:2021-Security Misconfiguration'],
      references: [{ title: 'CWE-1004: Sensitive Cookie Without HttpOnly', url: REF.cwe(1004) }],
    },
    remediationHint: 'Set `{ httpOnly: true, secure: true, sameSite: "lax" }` on session cookies.',
  },
  {
    id: 'js-open-redirect',
    title: 'Redirect target taken from request input',
    description:
      'Redirecting to a user-supplied URL enables convincing phishing links that appear to originate from your domain.',
    severity: 'medium',
    kind: 'sast',
    confidence: 'medium',
    languages: ['javascript', 'typescript'],
    patterns: [
      /\bres\.redirect\s*\(\s*(?:req\.|[A-Za-z_$][\w$]*\.(?:query|params|body))/,
      /window\.location(?:\.href)?\s*=\s*(?:[A-Za-z_$][\w$]*\.)?(?:searchParams|query|params)/,
    ],
    validate: all(notInComment, notInTests),
    taxonomy: {
      cwe: ['CWE-601'],
      owaspTop10: ['A01:2021-Broken Access Control'],
      references: [{ title: 'CWE-601: Open Redirect', url: REF.cwe(601) }],
    },
    remediationHint: 'Allowlist redirect destinations, or only permit same-origin relative paths.',
  },
  {
    id: 'js-nosql-injection',
    title: 'NoSQL query built from unvalidated request input',
    description:
      'Passing a request object straight into a MongoDB filter lets an attacker inject operators such as `$ne` or `$gt` to bypass authentication.',
    severity: 'high',
    kind: 'sast',
    confidence: 'medium',
    languages: ['javascript', 'typescript'],
    patterns: [
      /\.(?:find|findOne|findOneAndUpdate|updateOne|deleteOne|count)\s*\(\s*\{[^}]*:\s*req\.(?:body|query|params)\.[\w.]+\s*[,}]/,
      /\$where\s*:/,
    ],
    validate: all(notInComment, notInTests),
    taxonomy: {
      cwe: ['CWE-943'],
      owaspTop10: ['A03:2021-Injection'],
      references: [
        { title: 'CWE-943: Improper Neutralization in Data Query Logic', url: REF.cwe(943) },
      ],
    },
    remediationHint: 'Cast inputs to their expected primitive type before using them in a filter.',
  },
];

/* ------------------------------------------------------------------ */
/* Python                                                              */
/* ------------------------------------------------------------------ */

const pythonRules: Rule[] = [
  {
    id: 'py-sql-injection',
    title: 'SQL query built with string formatting',
    description:
      'f-strings, `%` formatting and `.format()` interpolate values directly into SQL, allowing the query structure to be rewritten by input.',
    severity: 'critical',
    kind: 'sast',
    confidence: 'medium',
    languages: ['python'],
    patterns: [
      /\b(?:execute|executemany|raw|execute_sql)\s*\(\s*f["'][^"']*\b(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b/i,
      /\b(?:execute|executemany|raw)\s*\(\s*["'][^"']*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^"']*["']\s*(?:%|\.format\()/i,
      /\bcursor\.execute\s*\([^,)]*\+/,
    ],
    validate: all(notInComment, notInTests),
    taxonomy: {
      cwe: ['CWE-89'],
      owaspTop10: ['A03:2021-Injection'],
      references: [{ title: 'CWE-89: SQL Injection', url: REF.cwe(89) }],
    },
    remediationHint:
      'Pass parameters separately: `cursor.execute("SELECT ... WHERE id = %s", (user_id,))`.',
  },
  {
    id: 'py-command-injection',
    title: 'Shell command executed with untrusted input',
    description:
      '`shell=True` and `os.system` route the command through a shell, so interpolated values can chain additional commands.',
    severity: 'critical',
    kind: 'sast',
    confidence: 'high',
    languages: ['python'],
    patterns: [
      /\bsubprocess\.(?:run|call|check_output|check_call|Popen)\s*\([^)]*shell\s*=\s*True/,
      /\bos\.(?:system|popen)\s*\(/,
      /\bcommands\.getoutput\s*\(/,
    ],
    validate: all(notInComment, notInTests),
    taxonomy: {
      cwe: ['CWE-78'],
      owaspTop10: ['A03:2021-Injection'],
      references: [{ title: 'CWE-78: OS Command Injection', url: REF.cwe(78) }],
    },
    remediationHint: 'Use `subprocess.run(["git", "clone", url])` with a list and `shell=False`.',
  },
  {
    id: 'py-code-injection',
    title: 'Dynamic code execution',
    description:
      '`eval`, `exec` and `compile` execute their argument as Python; any influence over that string is remote code execution.',
    severity: 'critical',
    kind: 'sast',
    confidence: 'high',
    languages: ['python'],
    patterns: [/\beval\s*\(/, /\bexec\s*\(/, /\bcompile\s*\([^)]*,\s*["']<string>["']/],
    excludePatterns: [/ast\.literal_eval/],
    validate: all(notInComment, notInTests),
    taxonomy: {
      cwe: ['CWE-94'],
      owaspTop10: ['A03:2021-Injection'],
      references: [{ title: 'CWE-94: Code Injection', url: REF.cwe(94) }],
    },
    remediationHint: 'Use `ast.literal_eval` for literals, or an explicit dispatch dictionary.',
  },
  {
    id: 'py-insecure-deserialization',
    title: 'Unsafe deserialization',
    description:
      '`pickle`, `marshal`, `shelve` and unsafe YAML loaders reconstruct arbitrary Python objects and can execute code during loading.',
    severity: 'critical',
    kind: 'sast',
    confidence: 'high',
    languages: ['python'],
    patterns: [
      /\bpickle\.loads?\s*\(/,
      /\bcPickle\.loads?\s*\(/,
      /\bmarshal\.loads?\s*\(/,
      /\byaml\.load\s*\((?![^)]*Loader\s*=\s*yaml\.(?:Safe|C?Safe)Loader)/,
      /\bdill\.loads?\s*\(/,
    ],
    validate: all(notInComment, notInTests),
    taxonomy: {
      cwe: ['CWE-502'],
      owaspTop10: ['A08:2021-Software and Data Integrity Failures'],
      references: [{ title: 'CWE-502: Deserialization of Untrusted Data', url: REF.cwe(502) }],
    },
    remediationHint: 'Use `json` for data interchange, or `yaml.safe_load` for YAML.',
  },
  {
    id: 'py-flask-debug-mode',
    title: 'Debug mode enabled',
    description:
      'Flask debug mode exposes the Werkzeug console, which grants interactive code execution to anyone who can reach the app.',
    severity: 'critical',
    kind: 'sast',
    confidence: 'high',
    languages: ['python'],
    patterns: [/\.run\s*\([^)]*debug\s*=\s*True/, /^\s*DEBUG\s*=\s*True/m],
    validate: all(notInComment, notInTests),
    taxonomy: {
      cwe: ['CWE-489', 'CWE-215'],
      owaspTop10: ['A05:2021-Security Misconfiguration'],
      references: [{ title: 'CWE-489: Active Debug Code', url: REF.cwe(489) }],
    },
    remediationHint: 'Drive debug from an environment variable and keep it false in production.',
  },
  {
    id: 'py-tls-verification-disabled',
    title: 'TLS certificate verification disabled',
    description:
      '`verify=False` disables certificate checking, so the connection can be transparently intercepted.',
    severity: 'critical',
    kind: 'sast',
    confidence: 'high',
    languages: ['python'],
    patterns: [
      /\bverify\s*=\s*False/,
      /ssl\._create_unverified_context/,
      /CERT_NONE/,
      /urllib3\.disable_warnings/,
    ],
    validate: all(notInComment, notInTests),
    taxonomy: {
      cwe: ['CWE-295'],
      owaspTop10: ['A07:2021-Identification and Authentication Failures'],
      references: [{ title: 'CWE-295: Improper Certificate Validation', url: REF.cwe(295) }],
    },
    remediationHint: 'Leave verification enabled and pass a CA bundle via `verify="/path/ca.pem"`.',
  },
  {
    id: 'py-xxe',
    title: 'XML parsed without disabling external entities',
    description:
      'Default Python XML parsers resolve external entities, enabling file disclosure and SSRF through a crafted document.',
    severity: 'high',
    kind: 'sast',
    confidence: 'medium',
    languages: ['python'],
    patterns: [
      /\betree\.(?:parse|fromstring)\s*\(/,
      /\bxml\.dom\.minidom\.parse/,
      /\bxml\.sax\.parse/,
      /\blxml\.etree\.(?:parse|fromstring)\s*\(/,
    ],
    excludePatterns: [/defusedxml/],
    validate: all(notInComment, notInTests),
    taxonomy: {
      cwe: ['CWE-611'],
      owaspTop10: ['A05:2021-Security Misconfiguration'],
      references: [{ title: 'CWE-611: XML External Entity Reference', url: REF.cwe(611) }],
    },
    remediationHint: 'Use the `defusedxml` package, which ships safe defaults.',
  },
  {
    id: 'py-weak-hash',
    title: 'Weak hash algorithm',
    description:
      'MD5 and SHA-1 are collision-broken and unsuitable for signatures, integrity checks, or password storage.',
    severity: 'medium',
    kind: 'sast',
    confidence: 'medium',
    languages: ['python'],
    patterns: [/\bhashlib\.(?:md5|sha1)\s*\(/],
    excludePatterns: [/usedforsecurity\s*=\s*False/],
    validate: all(notInComment, notInTests),
    taxonomy: {
      cwe: ['CWE-327', 'CWE-328'],
      owaspTop10: ['A02:2021-Cryptographic Failures'],
      references: [{ title: 'CWE-327: Broken Cryptographic Algorithm', url: REF.cwe(327) }],
    },
    remediationHint:
      'Use SHA-256 for integrity, and argon2/bcrypt/scrypt for passwords. Pass `usedforsecurity=False` for non-security digests.',
  },
  {
    id: 'py-assert-for-validation',
    title: 'Security check implemented with assert',
    description:
      '`assert` statements are removed entirely when Python runs with `-O`, silently deleting the check.',
    severity: 'medium',
    kind: 'sast',
    confidence: 'low',
    languages: ['python'],
    patterns: [/^\s*assert\s+.*(?:auth|permission|admin|token|valid|allow|role)/i],
    validate: all(notInComment, notInTests),
    taxonomy: {
      cwe: ['CWE-617'],
      references: [{ title: 'CWE-617: Reachable Assertion', url: REF.cwe(617) }],
    },
    remediationHint: 'Raise an explicit exception instead of asserting.',
  },
  {
    id: 'py-path-traversal',
    title: 'File path built from request input',
    description:
      'Joining request data into a path lets `../` sequences escape the intended directory.',
    severity: 'high',
    kind: 'sast',
    confidence: 'medium',
    languages: ['python'],
    patterns: [
      /\bopen\s*\(\s*(?:os\.path\.join\s*\()?[^)]*(?:request\.|params\[|args\.get|form\.get|json\[)/,
      /\bos\.path\.join\s*\([^)]*request\./,
      /\bsend_file\s*\([^)]*request\./,
    ],
    validate: all(notInComment, notInTests),
    taxonomy: {
      cwe: ['CWE-22'],
      owaspTop10: ['A01:2021-Broken Access Control'],
      references: [{ title: 'CWE-22: Path Traversal', url: REF.cwe(22) }],
    },
    remediationHint:
      'Resolve with `os.path.realpath` and verify the result is still under the intended base directory.',
  },
];

/* ------------------------------------------------------------------ */
/* Java                                                                */
/* ------------------------------------------------------------------ */

const javaRules: Rule[] = [
  {
    id: 'java-sql-injection',
    title: 'SQL statement built by concatenation',
    description:
      'Building SQL with `+` on a `Statement` allows the query structure to be altered by any interpolated value.',
    severity: 'critical',
    kind: 'sast',
    confidence: 'medium',
    languages: ['java'],
    // Java string literals are double-quoted, so the character class must allow
    // the single quotes that routinely appear *inside* a SQL literal
    // (`WHERE id = '" + id + "'`).
    patterns: [
      /\b(?:executeQuery|executeUpdate|execute)\s*\(\s*"[^"]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^"]*"\s*\+/i,
      /createStatement\s*\(\s*\)[^;]*execute/,
      /createQuery\s*\(\s*"[^"]*"\s*\+/,
    ],
    validate: all(notInComment, notInTests),
    taxonomy: {
      cwe: ['CWE-89'],
      owaspTop10: ['A03:2021-Injection'],
      references: [{ title: 'CWE-89: SQL Injection', url: REF.cwe(89) }],
    },
    remediationHint: 'Use `PreparedStatement` with `?` placeholders and `setString`/`setInt`.',
  },
  {
    id: 'java-command-injection',
    title: 'Runtime command execution with dynamic input',
    description:
      '`Runtime.exec` with a concatenated string is parsed as a command line, enabling injection of extra arguments or commands.',
    severity: 'critical',
    kind: 'sast',
    confidence: 'high',
    languages: ['java'],
    patterns: [
      /Runtime\.getRuntime\s*\(\s*\)\.exec\s*\([^)]*\+/,
      /new\s+ProcessBuilder\s*\([^)]*\+/,
    ],
    validate: all(notInComment, notInTests),
    taxonomy: {
      cwe: ['CWE-78'],
      owaspTop10: ['A03:2021-Injection'],
      references: [{ title: 'CWE-78: OS Command Injection', url: REF.cwe(78) }],
    },
    remediationHint:
      'Pass a `String[]` of arguments to `ProcessBuilder` so no shell parsing occurs.',
  },
  {
    id: 'java-insecure-deserialization',
    title: 'Java object deserialization of untrusted data',
    description:
      '`ObjectInputStream.readObject` instantiates arbitrary classes and is the basis of well-known gadget-chain RCE exploits.',
    severity: 'critical',
    kind: 'sast',
    confidence: 'high',
    languages: ['java'],
    patterns: [/new\s+ObjectInputStream\s*\(/, /\.readObject\s*\(\s*\)/, /XMLDecoder\s*\(/],
    validate: all(notInComment, notInTests),
    taxonomy: {
      cwe: ['CWE-502'],
      owaspTop10: ['A08:2021-Software and Data Integrity Failures'],
      references: [{ title: 'CWE-502: Deserialization of Untrusted Data', url: REF.cwe(502) }],
    },
    remediationHint:
      'Use JSON with an explicit schema, or apply a strict `ObjectInputFilter` allowlist.',
  },
  {
    id: 'java-xxe',
    title: 'XML parser allows external entities',
    description:
      'Java XML factories resolve DTDs and external entities by default, enabling file read and SSRF.',
    severity: 'high',
    kind: 'sast',
    confidence: 'medium',
    languages: ['java'],
    patterns: [
      /DocumentBuilderFactory\.newInstance\s*\(\s*\)/,
      /SAXParserFactory\.newInstance\s*\(\s*\)/,
      /XMLInputFactory\.newInstance\s*\(\s*\)/,
    ],
    excludePatterns: [/setFeature|disallow-doctype-decl|XMLConstants\.FEATURE_SECURE_PROCESSING/],
    validate: all(notInComment, notInTests),
    taxonomy: {
      cwe: ['CWE-611'],
      owaspTop10: ['A05:2021-Security Misconfiguration'],
      references: [{ title: 'CWE-611: XXE', url: REF.cwe(611) }],
    },
    remediationHint:
      'Call `factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`.',
  },
  {
    id: 'java-weak-crypto',
    title: 'Weak or misused cryptographic primitive',
    description:
      'DES, RC4, MD5, SHA-1 and ECB mode are broken or leak plaintext structure and must not protect real data.',
    severity: 'high',
    kind: 'sast',
    confidence: 'high',
    languages: ['java'],
    patterns: [
      /Cipher\.getInstance\s*\(\s*["'](?:DES|DESede|RC4|RC2|Blowfish)/i,
      /Cipher\.getInstance\s*\(\s*["'][^"']*\/ECB\//i,
      /MessageDigest\.getInstance\s*\(\s*["'](?:MD5|SHA-?1)["']/i,
    ],
    validate: all(notInComment, notInTests),
    taxonomy: {
      cwe: ['CWE-327'],
      owaspTop10: ['A02:2021-Cryptographic Failures'],
      references: [{ title: 'CWE-327: Broken Cryptographic Algorithm', url: REF.cwe(327) }],
    },
    remediationHint: 'Use `AES/GCM/NoPadding` for encryption and SHA-256 or better for digests.',
  },
  {
    id: 'java-insecure-random',
    title: 'Predictable random source for security value',
    description:
      '`java.util.Random` is a linear congruential generator whose output can be predicted from a few samples.',
    severity: 'high',
    kind: 'sast',
    confidence: 'medium',
    languages: ['java'],
    patterns: [/new\s+Random\s*\(/],
    validate: all(
      notInComment,
      notInTests,
      contextMatches(/token|secret|password|key|nonce|salt|session|otp|csrf/i),
    ),
    taxonomy: {
      cwe: ['CWE-330', 'CWE-338'],
      owaspTop10: ['A02:2021-Cryptographic Failures'],
      references: [{ title: 'CWE-330: Use of Insufficiently Random Values', url: REF.cwe(330) }],
    },
    remediationHint: 'Use `java.security.SecureRandom`.',
  },
  {
    id: 'java-ldap-injection',
    title: 'LDAP filter built by concatenation',
    description:
      'Unescaped input in an LDAP filter can broaden the search and bypass authentication checks.',
    severity: 'high',
    kind: 'sast',
    confidence: 'medium',
    languages: ['java'],
    patterns: [/\bsearch\s*\([^)]*["'][^"']*\(\s*(?:uid|cn|mail)\s*=[^"']*["']\s*\+/i],
    validate: all(notInComment, notInTests),
    taxonomy: {
      cwe: ['CWE-90'],
      owaspTop10: ['A03:2021-Injection'],
      references: [{ title: 'CWE-90: LDAP Injection', url: REF.cwe(90) }],
    },
    remediationHint: 'Escape filter values per RFC 4515 or use parameterized search APIs.',
  },
];

/* ------------------------------------------------------------------ */
/* Go                                                                  */
/* ------------------------------------------------------------------ */

const goRules: Rule[] = [
  {
    id: 'go-sql-injection',
    title: 'SQL query assembled with Sprintf or concatenation',
    description:
      '`fmt.Sprintf` into a query string bypasses the driver placeholder mechanism entirely.',
    severity: 'critical',
    kind: 'sast',
    confidence: 'medium',
    languages: ['go'],
    patterns: [
      /\b(?:Query|QueryRow|Exec|QueryContext|ExecContext)\s*\(\s*(?:ctx\s*,\s*)?fmt\.Sprintf\s*\(/,
      /\b(?:Query|QueryRow|Exec)\s*\(\s*["`][^"`]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^"`]*["`]\s*\+/i,
    ],
    validate: all(notInComment, notInTests),
    taxonomy: {
      cwe: ['CWE-89'],
      owaspTop10: ['A03:2021-Injection'],
      references: [{ title: 'CWE-89: SQL Injection', url: REF.cwe(89) }],
    },
    remediationHint: 'Use placeholders: `db.Query("SELECT * FROM users WHERE id = $1", id)`.',
  },
  {
    id: 'go-command-injection',
    title: 'Command executed through a shell',
    description:
      'Invoking `sh -c` with an interpolated string reintroduces shell metacharacter injection.',
    severity: 'critical',
    kind: 'sast',
    confidence: 'high',
    languages: ['go'],
    patterns: [
      /exec\.Command\s*\(\s*["'](?:\/bin\/)?(?:sh|bash|zsh|cmd)["']\s*,\s*["']-c["']/,
      /exec\.Command\s*\(\s*fmt\.Sprintf/,
    ],
    validate: all(notInComment, notInTests),
    taxonomy: {
      cwe: ['CWE-78'],
      owaspTop10: ['A03:2021-Injection'],
      references: [{ title: 'CWE-78: OS Command Injection', url: REF.cwe(78) }],
    },
    remediationHint: 'Call the binary directly: `exec.Command("git", "clone", url)`.',
  },
  {
    id: 'go-tls-verification-disabled',
    title: 'TLS verification disabled',
    description:
      '`InsecureSkipVerify: true` accepts any certificate, defeating transport security.',
    severity: 'critical',
    kind: 'sast',
    confidence: 'high',
    languages: ['go'],
    patterns: [/InsecureSkipVerify\s*:\s*true/],
    validate: all(notInComment, notInTests),
    taxonomy: {
      cwe: ['CWE-295'],
      owaspTop10: ['A07:2021-Identification and Authentication Failures'],
      references: [{ title: 'CWE-295: Improper Certificate Validation', url: REF.cwe(295) }],
    },
    remediationHint: 'Configure `RootCAs` with the expected CA instead of skipping verification.',
  },
  {
    id: 'go-weak-crypto',
    title: 'Weak cryptographic algorithm',
    description: 'MD5, SHA-1, DES and RC4 are unsuitable for any security purpose.',
    severity: 'medium',
    kind: 'sast',
    confidence: 'high',
    languages: ['go'],
    patterns: [/crypto\/(?:md5|sha1|des|rc4)/, /\b(?:md5|sha1)\.(?:New|Sum)\s*\(/],
    validate: all(notInComment, notInTests),
    taxonomy: {
      cwe: ['CWE-327'],
      owaspTop10: ['A02:2021-Cryptographic Failures'],
      references: [{ title: 'CWE-327: Broken Cryptographic Algorithm', url: REF.cwe(327) }],
    },
    remediationHint: 'Use `crypto/sha256` and AES-GCM.',
  },
  {
    id: 'go-weak-random',
    title: 'math/rand used for a security value',
    description: '`math/rand` is deterministic and predictable; it must not generate secrets.',
    severity: 'high',
    kind: 'sast',
    confidence: 'medium',
    languages: ['go'],
    patterns: [/\brand\.(?:Intn?|Int31|Int63|Float64|Read)\s*\(/],
    excludePatterns: [/crypto\/rand/],
    validate: all(
      notInComment,
      notInTests,
      contextMatches(/token|secret|password|key|nonce|salt|session|otp|csrf/i),
    ),
    taxonomy: {
      cwe: ['CWE-338'],
      owaspTop10: ['A02:2021-Cryptographic Failures'],
      references: [{ title: 'CWE-338: Weak PRNG', url: REF.cwe(338) }],
    },
    remediationHint: 'Import `crypto/rand` instead of `math/rand`.',
  },
  {
    id: 'go-path-traversal',
    title: 'File path joined from request input',
    description: 'User-controlled path segments allow escaping the intended directory with `../`.',
    severity: 'high',
    kind: 'sast',
    confidence: 'medium',
    languages: ['go'],
    patterns: [
      /(?:os\.(?:Open|ReadFile|Create)|ioutil\.ReadFile)\s*\(\s*(?:filepath\.Join\s*\()?[^)]*(?:r\.URL|mux\.Vars|c\.Param|r\.FormValue)/,
    ],
    validate: all(notInComment, notInTests),
    taxonomy: {
      cwe: ['CWE-22'],
      owaspTop10: ['A01:2021-Broken Access Control'],
      references: [{ title: 'CWE-22: Path Traversal', url: REF.cwe(22) }],
    },
    remediationHint: 'Use `filepath.Clean` then verify the result still has the intended prefix.',
  },
];

/* ------------------------------------------------------------------ */
/* Rust, C#, PHP                                                       */
/* ------------------------------------------------------------------ */

const rustRules: Rule[] = [
  {
    id: 'rust-command-injection',
    title: 'Command executed through a shell',
    description: 'Spawning `sh -c` with a formatted string reintroduces shell injection.',
    severity: 'critical',
    kind: 'sast',
    confidence: 'high',
    languages: ['rust'],
    patterns: [
      /Command::new\s*\(\s*"(?:sh|bash|cmd)"\s*\)[^;]*\.arg\s*\(\s*"-c"/,
      /Command::new\s*\(\s*&?format!/,
    ],
    validate: all(notInComment, notInTests),
    taxonomy: {
      cwe: ['CWE-78'],
      owaspTop10: ['A03:2021-Injection'],
      references: [{ title: 'CWE-78: OS Command Injection', url: REF.cwe(78) }],
    },
    remediationHint: 'Invoke the target binary directly and pass arguments via `.arg()`.',
  },
  {
    id: 'rust-unsafe-block',
    title: 'Unsafe block bypasses memory safety guarantees',
    description:
      '`unsafe` opts out of the borrow checker. Each block needs justification because memory-safety bugs re-enter here.',
    severity: 'low',
    kind: 'sast',
    confidence: 'high',
    languages: ['rust'],
    patterns: [/\bunsafe\s*\{/],
    validate: all(notInComment, notInTests),
    taxonomy: {
      cwe: ['CWE-119'],
      references: [{ title: 'CWE-119: Improper Restriction of Memory Buffer', url: REF.cwe(119) }],
    },
    remediationHint:
      'Document the invariant that makes the block sound, or use a safe abstraction.',
  },
  {
    id: 'rust-sql-injection',
    title: 'SQL query built with format!',
    description: '`format!` into a SQL string bypasses parameter binding.',
    severity: 'critical',
    kind: 'sast',
    confidence: 'medium',
    languages: ['rust'],
    patterns: [/\b(?:query|execute)\s*\(\s*&?format!\s*\(/],
    validate: all(notInComment, notInTests),
    taxonomy: {
      cwe: ['CWE-89'],
      owaspTop10: ['A03:2021-Injection'],
      references: [{ title: 'CWE-89: SQL Injection', url: REF.cwe(89) }],
    },
    remediationHint: 'Use `sqlx::query!` with bind parameters.',
  },
  {
    id: 'rust-tls-verification-disabled',
    title: 'TLS certificate validation disabled',
    description: 'Accepting invalid certificates makes the connection interceptable.',
    severity: 'critical',
    kind: 'sast',
    confidence: 'high',
    languages: ['rust'],
    patterns: [
      /danger_accept_invalid_certs\s*\(\s*true\s*\)/,
      /danger_accept_invalid_hostnames\s*\(\s*true\s*\)/,
    ],
    validate: notInComment,
    taxonomy: {
      cwe: ['CWE-295'],
      references: [{ title: 'CWE-295: Improper Certificate Validation', url: REF.cwe(295) }],
    },
    remediationHint: 'Add the required CA to the client certificate store instead.',
  },
];

const csharpRules: Rule[] = [
  {
    id: 'csharp-sql-injection',
    title: 'SQL command built by concatenation or interpolation',
    description:
      'Interpolated strings in `SqlCommand` bypass parameter binding and allow query manipulation.',
    severity: 'critical',
    kind: 'sast',
    confidence: 'medium',
    languages: ['csharp'],
    patterns: [
      /new\s+SqlCommand\s*\(\s*(?:\$"|["'][^"']*["']\s*\+)/,
      /\bExecuteSqlRaw\s*\(\s*\$"/,
      /CommandText\s*=\s*(?:\$"|["'][^"']*["']\s*\+)/,
    ],
    validate: all(notInComment, notInTests),
    taxonomy: {
      cwe: ['CWE-89'],
      owaspTop10: ['A03:2021-Injection'],
      references: [{ title: 'CWE-89: SQL Injection', url: REF.cwe(89) }],
    },
    remediationHint: 'Use `cmd.Parameters.AddWithValue("@id", id)` with placeholders.',
  },
  {
    id: 'csharp-insecure-deserialization',
    title: 'Unsafe .NET deserialization',
    description:
      '`BinaryFormatter`, `LosFormatter` and `NetDataContractSerializer` are known RCE vectors and are deprecated by Microsoft.',
    severity: 'critical',
    kind: 'sast',
    confidence: 'high',
    languages: ['csharp'],
    patterns: [
      /new\s+BinaryFormatter\s*\(/,
      /new\s+LosFormatter\s*\(/,
      /NetDataContractSerializer/,
      /TypeNameHandling\s*=\s*TypeNameHandling\.(?:All|Objects|Auto)/,
    ],
    validate: all(notInComment, notInTests),
    taxonomy: {
      cwe: ['CWE-502'],
      owaspTop10: ['A08:2021-Software and Data Integrity Failures'],
      references: [{ title: 'CWE-502: Deserialization of Untrusted Data', url: REF.cwe(502) }],
    },
    remediationHint: 'Use `System.Text.Json` with a known target type.',
  },
  {
    id: 'csharp-tls-verification-disabled',
    title: 'Certificate validation callback always succeeds',
    description:
      'Returning `true` unconditionally from the certificate validation callback accepts every certificate.',
    severity: 'critical',
    kind: 'sast',
    confidence: 'high',
    languages: ['csharp'],
    patterns: [
      /ServerCertificateValidationCallback\s*(?:\+)?=\s*(?:delegate|\()[^;]*true/,
      /ServerCertificateCustomValidationCallback\s*=\s*[^;]*true/,
    ],
    validate: notInComment,
    taxonomy: {
      cwe: ['CWE-295'],
      references: [{ title: 'CWE-295: Improper Certificate Validation', url: REF.cwe(295) }],
    },
    remediationHint: 'Validate the chain, or pin the expected certificate thumbprint.',
  },
  {
    id: 'csharp-weak-crypto',
    title: 'Weak cryptographic algorithm',
    description: 'MD5, SHA-1, DES, RC2 and TripleDES do not provide adequate security margins.',
    severity: 'medium',
    kind: 'sast',
    confidence: 'high',
    languages: ['csharp'],
    patterns: [/(?:MD5|SHA1|DES|RC2|TripleDES)(?:CryptoServiceProvider|\.Create)\s*\(/],
    validate: all(notInComment, notInTests),
    taxonomy: {
      cwe: ['CWE-327'],
      owaspTop10: ['A02:2021-Cryptographic Failures'],
      references: [{ title: 'CWE-327: Broken Cryptographic Algorithm', url: REF.cwe(327) }],
    },
    remediationHint: 'Use `SHA256.Create()` and `Aes.Create()` with GCM.',
  },
];

const phpRules: Rule[] = [
  {
    id: 'php-sql-injection',
    title: 'SQL query built with interpolated variables',
    description:
      'PHP interpolates variables inside double-quoted strings, so a query written this way is directly injectable.',
    severity: 'critical',
    kind: 'sast',
    confidence: 'medium',
    languages: ['php'],
    // Two shapes. First: a double-quoted literal, which is the only kind PHP
    // interpolates — and `mysqli_query` takes the connection first, so the
    // query may be the second argument. Second: explicit `.` concatenation.
    patterns: [
      /\b(?:mysqli?_query|mysql_query|->query|->exec)\s*\(\s*(?:\$\w+\s*,\s*)?"[^"]*\$\w/,
      /\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^;"]*["']\s*\.\s*\$/i,
    ],
    validate: all(notInComment, notInTests),
    taxonomy: {
      cwe: ['CWE-89'],
      owaspTop10: ['A03:2021-Injection'],
      references: [{ title: 'CWE-89: SQL Injection', url: REF.cwe(89) }],
    },
    remediationHint: 'Use PDO prepared statements with bound parameters.',
  },
  {
    id: 'php-command-injection',
    title: 'Shell execution with interpolated input',
    description: '`system`, `exec`, `shell_exec` and backticks all pass their argument to a shell.',
    severity: 'critical',
    kind: 'sast',
    confidence: 'high',
    languages: ['php'],
    patterns: [
      /\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(\s*[^)]*\$/,
      /`[^`]*\$[^`]*`/,
    ],
    validate: all(notInComment, notInTests),
    taxonomy: {
      cwe: ['CWE-78'],
      owaspTop10: ['A03:2021-Injection'],
      references: [{ title: 'CWE-78: OS Command Injection', url: REF.cwe(78) }],
    },
    remediationHint:
      'Use `escapeshellarg()` on every interpolated value, or avoid the shell entirely.',
  },
  {
    id: 'php-code-injection',
    title: 'Dynamic code evaluation',
    description:
      '`eval`, `assert` on a string, and `create_function` execute their argument as PHP.',
    severity: 'critical',
    kind: 'sast',
    confidence: 'high',
    languages: ['php'],
    patterns: [/\beval\s*\(/, /\bcreate_function\s*\(/, /\bassert\s*\(\s*["'$]/],
    validate: all(notInComment, notInTests),
    taxonomy: {
      cwe: ['CWE-94'],
      owaspTop10: ['A03:2021-Injection'],
      references: [{ title: 'CWE-94: Code Injection', url: REF.cwe(94) }],
    },
    remediationHint: 'Replace dynamic evaluation with an explicit dispatch table.',
  },
  {
    id: 'php-insecure-deserialization',
    title: 'unserialize() on untrusted data',
    description:
      'PHP object injection through `unserialize` can trigger magic methods and lead to code execution.',
    severity: 'critical',
    kind: 'sast',
    confidence: 'high',
    languages: ['php'],
    patterns: [/\bunserialize\s*\(/],
    excludePatterns: [/allowed_classes\s*=>\s*false/],
    validate: all(notInComment, notInTests),
    taxonomy: {
      cwe: ['CWE-502'],
      owaspTop10: ['A08:2021-Software and Data Integrity Failures'],
      references: [{ title: 'CWE-502: Deserialization of Untrusted Data', url: REF.cwe(502) }],
    },
    remediationHint: 'Use `json_decode`, or pass `["allowed_classes" => false]`.',
  },
  {
    id: 'php-file-inclusion',
    title: 'Dynamic file inclusion',
    description:
      '`include`/`require` with a variable path enables local and remote file inclusion attacks.',
    severity: 'critical',
    kind: 'sast',
    confidence: 'high',
    languages: ['php'],
    patterns: [
      /\b(?:include|include_once|require|require_once)\s*(?:\(\s*)?[^;)]*\$(?:_GET|_POST|_REQUEST)/,
    ],
    validate: all(notInComment, notInTests),
    taxonomy: {
      cwe: ['CWE-98'],
      owaspTop10: ['A03:2021-Injection'],
      references: [{ title: 'CWE-98: PHP Remote File Inclusion', url: REF.cwe(98) }],
    },
    remediationHint: 'Map the input to a fixed allowlist of includable files.',
  },
];

/* ------------------------------------------------------------------ */
/* Language-agnostic                                                   */
/* ------------------------------------------------------------------ */

const commonRules: Rule[] = [
  {
    id: 'common-hardcoded-crypto-key',
    title: 'Cryptographic key or IV hardcoded in source',
    description:
      'A key committed to source control is available to everyone with repository access and cannot be rotated without a code change.',
    severity: 'high',
    kind: 'sast',
    confidence: 'medium',
    patterns: [
      /(?:secret_?key|private_?key|encryption_?key|signing_?key|iv)\s*[:=]\s*["'][A-Za-z0-9+/=_-]{16,}["']/i,
    ],
    excludePatterns: [
      /process\.env|os\.environ|System\.getenv|getenv|<%=|\$\{|example|placeholder|xxxx|your[-_]/i,
    ],
    validate: all(notInComment, notInTests),
    taxonomy: {
      cwe: ['CWE-321', 'CWE-798'],
      owaspTop10: ['A02:2021-Cryptographic Failures'],
      references: [{ title: 'CWE-321: Hard-coded Cryptographic Key', url: REF.cwe(321) }],
    },
    remediationHint: 'Load keys from a secret manager or environment variable at runtime.',
  },
  {
    id: 'common-sensitive-data-logged',
    title: 'Potentially sensitive value written to logs',
    description:
      'Credentials and tokens in log output persist in aggregation systems long after the request, often with far wider access than the application itself.',
    severity: 'medium',
    kind: 'sast',
    confidence: 'low',
    patterns: [
      /\b(?:console\.(?:log|info|debug)|print|println|printf|logger?\.(?:info|debug|log|warn))\s*\([^)]*\b(?:password|passwd|secret|token|api[_-]?key|credential|authorization)\b/i,
    ],
    validate: all(notInComment, notInTests, (m) => {
      // The first argument of a log call is the human-readable message. A
      // sensitive word appearing only there — `logger.debug('Token verification
      // failed', { error })` — is describing what happened, not logging a
      // credential. Fire only when the word also appears outside that literal.
      const withoutMessage = m.line.replace(
        /(\b(?:console\.\w+|logger?\.\w+|print\w*)\s*\(\s*)(['"`])(?:\\.|(?!\2)[^\\])*\2/i,
        '$1',
      );
      return /\b(?:password|passwd|secret|token|api[_-]?key|credential|authorization)\b/i.test(
        withoutMessage,
      );
    }),
    taxonomy: {
      cwe: ['CWE-532'],
      owaspTop10: ['A09:2021-Security Logging and Monitoring Failures'],
      references: [
        { title: 'CWE-532: Insertion of Sensitive Information into Log File', url: REF.cwe(532) },
      ],
    },
    remediationHint:
      'Redact sensitive fields before logging, or log an identifier instead of the value.',
  },
  {
    id: 'common-todo-security',
    title: 'Unresolved security TODO',
    description:
      'A comment acknowledging a missing security control. Tracked so it is triaged rather than forgotten.',
    severity: 'info',
    kind: 'sast',
    confidence: 'high',
    patterns: [
      /(?:\/\/|#|\/\*|<!--)\s*(?:TODO|FIXME|HACK|XXX)\b[^\n]*\b(?:security|secure|auth|vulnerab|injection|sanitiz|validat|encrypt|permission)/i,
    ],
    taxonomy: { cwe: ['CWE-546'] },
    remediationHint: 'Convert the comment into a tracked issue with an owner and a date.',
  },
];

export const SAST_RULES: Rule[] = [
  ...jsRules,
  ...pythonRules,
  ...javaRules,
  ...goRules,
  ...rustRules,
  ...csharpRules,
  ...phpRules,
  ...commonRules,
];

export const RULES_BY_LANGUAGE = SAST_RULES.reduce<Record<string, Rule[]>>((acc, rule) => {
  const keys = rule.languages?.length ? rule.languages : ['*'];
  for (const key of keys) {
    (acc[key] ??= []).push(rule);
  }
  return acc;
}, {});
