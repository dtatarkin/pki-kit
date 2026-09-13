import "just.just"

[doc("Run a Python command via uv")]
[group("project")]
[positional-arguments]
python-run *args:
    @uv run "$@"

[doc("Bump the dev version")]
[group("project")]
bump-dev:
    uv version --bump dev

[doc("Build the package")]
[group("project")]
build:
    uv build

[doc("Publish the package to PyPI")]
[group("project")]
publish:
    just python-run dotenv --file pypi.env run uv publish dist/*

[doc("Run pre-commit with custom arguments")]
[group("lint")]
[positional-arguments]
pre-commit *args:
    just python-run pre-commit "$@"

# Deliberately left without a shebang, and `just-lint` reports it as such. This
# repository is released: someone may be at any pin, and putting a two-line body
# under one shell with `set -euo pipefail` changes how the recipe executes, which
# is the one thing release discipline exists to prevent. Help text and argument
# handling are what a justfile here may change; this is neither.

[doc("Run all checks (pre-commit hooks, lint, typecheck)")]
[group("lint")]
lint:
    @# Retry once: hooks that auto-fix files (ruff, trailing-whitespace, etc.) fail on first run; second run verifies fixes.
    just pre-commit run --all-files

[doc("Run tests with pytest")]
[group("project")]
[positional-arguments]
test *args:
    just python-run pytest "$@"

[doc("Run lint and tests")]
[group("project")]
check: lint test
