# Remediation Patterns — Concrete Code Changes

Load this file for Step 5 (generate remediation) of the main skill. The goal: never end a
`FIX_REQUIRED` or `MUST_FIX_NO_PATCH` finding with just a version number — produce an actual
diff/snippet the developer can apply, scoped to how the dependency is declared in this repo.

Always show the change as a fenced diff (`+`/`-` lines) against the real file found during Step 3,
not a generic example — use the actual file path, current version, and surrounding syntax from
the repo you already read.

---

## 1. Direct dependency — simple version bump

**npm** (`package.json`):
```diff
   "dependencies": {
-    "ws": "7.5.10",
+    "ws": "7.5.11",
   }
```
Follow with: `npm install && npm ls ws` to confirm resolution, and note whether package-lock.json
needs to be committed alongside.

**Maven** (`pom.xml`):
```diff
   <dependency>
     <groupId>org.springframework</groupId>
     <artifactId>spring-core</artifactId>
-    <version>5.3.20</version>
+    <version>5.3.39</version>
   </dependency>
```

**Gradle**:
```diff
- implementation 'org.springframework:spring-core:5.3.20'
+ implementation 'org.springframework:spring-core:5.3.39'
```

**pip** (`requirements.txt`):
```diff
- requests==2.25.1
+ requests==2.32.0
```

**Poetry** (`pyproject.toml`):
```diff
- requests = "2.25.1"
+ requests = "^2.32.0"
```

---

## 2. Transitive dependency — forced override (no direct declaration exists to bump)

**npm `overrides`** (`package.json`) — global force:
```diff
   "dependencies": { ... },
+  "overrides": {
+    "ws": "7.5.11"
+  }
```
Scoped to one parent only (safer, avoids affecting unrelated usages of the same package):
```diff
+  "overrides": {
+    "multiple-cucumber-html-reporter": {
+      "ws": "7.5.11"
+    }
+  }
```

**Yarn `resolutions`** (`package.json`):
```diff
+  "resolutions": {
+    "ws": "7.5.11"
+  }
```

**Maven `<dependencyManagement>`** (root/parent `pom.xml`):
```diff
   <dependencyManagement>
     <dependencies>
+      <dependency>
+        <groupId>com.fasterxml.jackson.core</groupId>
+        <artifactId>jackson-databind</artifactId>
+        <version>2.17.1</version>
+      </dependency>
     </dependencies>
   </dependencyManagement>
```

**Gradle constraints** (`build.gradle`):
```diff
   dependencies {
+    constraints {
+      implementation('com.fasterxml.jackson.core:jackson-databind:2.17.1') {
+        because 'CVE-2026-XXXXX — force safe version of transitive dep'
+      }
+    }
   }
```

**pip constraints file**:
```diff
+ # constraints.txt
+ some-transitive-pkg==2.3.1
```
```
pip install -r requirements.txt -c constraints.txt
```

**Poetry** — pin the transitive package directly even though it's not a direct dependency:
```
poetry add some-transitive-pkg@2.3.1
```

After any override: **always re-run the dependency tree command** (see language-patterns.md) to
confirm the forced version actually took effect and didn't get silently ignored due to an
unsatisfiable range.

---

## 3. No fixed version exists, but the code is prod-reachable — alternative mitigations

Pick the most targeted option; prefer the smallest blast-radius change.

### 3a. Wrap/sanitize the call site
If the vulnerability is triggered by a specific unsafe input pattern (e.g. unbounded input size,
unsanitized key names), add a guard at the call site rather than waiting on the library:
```diff
+ const MAX_FRAGMENT_SIZE = 1024 * 64;
  ws.on('message', (data) => {
+   if (data.length > MAX_FRAGMENT_SIZE) {
+     ws.terminate();
+     return;
+   }
    handleMessage(data);
  });
```
State clearly in the report that this is a compensating control, not a real fix — the underlying
library code is still vulnerable, you're just preventing the trigger condition at your boundary.

### 3b. Feature-flag / disable the affected code path
If the vulnerable feature isn't essential:
```diff
- app.use('/admin/debug-console', debugConsoleRouter);
+ if (process.env.ENABLE_DEBUG_CONSOLE === 'true') {
+   app.use('/admin/debug-console', debugConsoleRouter);
+ }
```
with the flag defaulting to disabled in production config.

### 3c. Replace the library
When the package is abandoned or has a maintained fork/alternative:
- Name the specific replacement (check it actually resolves the CVE, not just "seems similar").
- Estimate migration effort honestly — API-compatible drop-in replacements are 🟡 Medium; anything
  requiring call-site rewrites across the codebase is 🔴 High.

### 3d. Vendor a patched fork
If no maintained alternative exists and the fix is small (e.g. a one-line patch is publicly
available in the upstream repo's unreleased commit), fork the package, apply the patch, and point
your package manager at the fork:
```diff
   "dependencies": {
-    "some-lib": "1.2.3",
+    "some-lib": "github:your-org/some-lib-patched#fix-cve-2026-xxxx",
   }
```
Flag this as a maintenance liability in the report — you now own tracking upstream releases
manually for this package.

### 3e. Network/infrastructure-level control
When no code-level mitigation is practical (e.g. the vulnerable path is deep in a transitive
dependency with no wrapper point): rate-limiting, WAF rule, or network segmentation. This is
outside the codebase — state it as a recommendation to the platform/security team, not a code
diff, and still require a `reviewBy` date since it's a compensating control, not a fix.

---

## 4. Always include after any suggested change

- **What to re-test**: name the specific behavior (e.g. "WebSocket reconnect under fragmented
  frames," "JSON deserialization of nested objects") — not "run the full test suite" as a
  substitute for actually identifying what changed.
- **Breaking-change risk**: state explicitly if the new version's changelog/release notes show
  any API or behavior change since the current version, or if you couldn't confirm (say so rather
  than assuming "patch version = safe").
- **Blast radius**: for overrides, name every other place in the tree that resolves to the same
  package, since a forced version affects all of them, not just the vulnerable parent.
