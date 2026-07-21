# Language/Ecosystem Search Patterns

Load this file only when doing Step 3 (reachability analysis) of the main skill. Use the
commands below as a starting point, scoped to the specific package under investigation — never
run a generic "scan everything" pass.

For each ecosystem: (1) how to find import/usage sites, (2) how to tell prod vs non-prod source,
(3) how to build the dependency tree once per run.

---

## JavaScript / TypeScript (npm, yarn, pnpm) — Angular, React, Node

**Find usage:**
```
rg -n "from ['\"]<pkg>['\"]" --type ts --type js
rg -n "require\(['\"]<pkg>['\"]\)" --type ts --type js
rg -n "import .* ['\"]<pkg>(/|['\"])" src/ app/
```

**Prod vs non-prod:**
- Non-prod if the only matches are under: `test/`, `tests/`, `__tests__/`, `*.test.ts`,
  `*.spec.ts`, `cypress/`, `e2e/`, `webpack.config.js`, `vite.config.ts`, `jest.config.js`,
  `.storybook/`.
- For Angular/React apps built into a static bundle: check whether the importing file is part of
  a lazy-loaded module/route that's actually included in `angular.json` / build config, not an
  unused feature module.
- Confirm devDependency-only packages aren't imported from anything under `src/app` or
  equivalent production source root — `npm ls --omit=dev` shows what's actually eligible to ship.

**Dependency tree (once per run):**
```
npm ls <pkg>
npm ls --omit=dev
```

---

## Java — Maven

**Find usage:**
```
grep -rn "import <package.path>" src/main/java/
grep -rn "import <package.path>" src/test/java/
```
Check both, but treat matches under `src/main/java` as prod-reachable and `src/test/java` as
non-prod (Maven's standard directory layout enforces this split; trust it unless the project
overrides `sourceDirectory`/`testSourceDirectory` in `pom.xml`, which is worth a quick check).

**Prod vs non-prod:**
- `<scope>test</scope>` or `<scope>provided</scope>` dependencies generally don't ship in the
  final artifact — confirm by checking the packaging plugin config (`maven-war-plugin`,
  `maven-shade-plugin`, `spring-boot-maven-plugin`) for exclusions.
- For Spring Boot fat JARs: `jar tf target/*.jar | grep <artifact-name>` after a build confirms
  whether the class files actually landed in the shipped JAR — this is the most reliable check
  when scope rules are ambiguous or overridden.

**Dependency tree (once per run):**
```
mvn dependency:tree -Dincludes=<groupId>:<artifactId>
```

---

## Java/Kotlin — Gradle

**Find usage:**
```
grep -rn "import <package.path>" src/main/
grep -rn "import <package.path>" src/test/
```

**Prod vs non-prod:**
- `testImplementation`/`testRuntimeOnly` configurations don't ship; `implementation`/`api`/
  `runtimeOnly` do.
- Check `build.gradle`/`build.gradle.kts` for which configuration declared the dependency
  (directly, or trace which parent brought it in via `./gradlew dependencies`).

**Dependency tree (once per run):**
```
./gradlew dependencies --configuration runtimeClasspath
```

---

## Python — pip / venv

**Find usage:**
```
grep -rn "^import <pkg>\|^from <pkg>" --include=*.py .
```

**Prod vs non-prod:**
- Check `requirements.txt` vs `requirements-dev.txt`/`requirements-test.txt` split if the project
  uses one.
- Non-prod if only imported from `tests/`, `test_*.py`, `conftest.py`, `setup.py`,
  `noxfile.py`/`tox.ini` tooling.
- For containerized deployments, check the `Dockerfile`'s final stage — does it `pip install -r
  requirements.txt` (prod-only) or copy a venv built from a dev requirements file?

**Dependency tree (once per run):**
```
pip show <pkg>
pipdeptree --packages <pkg>
```

---

## Python — Poetry

**Find usage:** same `grep`/`rg` pattern as pip above.

**Prod vs non-prod:**
- Check `pyproject.toml` — dependencies under `[tool.poetry.group.dev.dependencies]` (or legacy
  `dev-dependencies`) are excluded from `poetry install --only main` / `--without dev`, which is
  what production builds should use. Confirm the Dockerfile/CI actually passes that flag —
  don't assume.

**Dependency tree (once per run):**
```
poetry show <pkg> --tree
```

---

## iOS — CocoaPods / Swift Package Manager

**Find usage:**
```
grep -rn "import <ModuleName>" --include=*.swift .
```

**Prod vs non-prod:**
- Check the target membership in `.xcodeproj`/`Package.swift` — a pod/package linked only to a
  test target (not the main app target) won't ship in the App Store binary.
- `pod list` / `Package.resolved` shows what's resolved; target membership in Xcode determines
  what actually links into the shipped binary.

---

## General notes

- Always scope searches to the specific package/API named in the advisory — never a blanket
  "search everything for security issues" pass; that defeats the token-saving design.
- When a match is found, open only that file (not the whole directory) to confirm the call
  actually exercises the vulnerable code path (e.g. constructs the object, calls the specific
  method) rather than just referencing an unrelated export from the same package.
- If a project's structure doesn't match these conventions (custom source roots, monorepo with
  shared packages, non-standard build layout), say so explicitly and ask once rather than
  guessing silently.
