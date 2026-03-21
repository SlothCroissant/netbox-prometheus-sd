# Commit Message Convention

Follow the [Conventional Commits](https://www.conventionalcommits.org/) format for semantic-release compatibility.

## Format

```
<type>(<optional scope>): <description>

[optional body]

[optional footer(s)]
```

## Allowed Types

| Type | Purpose | Release |
|------|---------|---------|
| `feat` | New feature | **minor** |
| `fix` | Bug fix | **patch** |
| `perf` | Performance improvement | **patch** |
| `build` | Build system / dependencies | no release |
| `chore` | Maintenance tasks | no release |
| `ci` | CI/CD changes | no release |
| `docs` | Documentation only | no release |
| `style` | Code style (formatting, whitespace) | no release |
| `refactor` | Code change that neither fixes a bug nor adds a feature | no release |
| `test` | Adding or updating tests | no release |

## Breaking Changes

Append `!` after the type/scope or add `BREAKING CHANGE:` in the footer to trigger a **major** release:

```
feat!: remove legacy API endpoint
```

## Examples

```
feat: add DNS target endpoint
fix: handle empty custom_fields in IP response
perf: cache NetBox API responses
ci: add Trivy scan to Docker workflow
chore: update Alpine base image
docs: add API usage examples to README
refactor: extract label building into helper
test: add unit tests for pagination logic
build: switch to multi-stage Docker build
style: fix indentation in app.py
```
