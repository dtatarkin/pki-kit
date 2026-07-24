import "just.just"

# Run a Python command via uv
[group("project")]
python-run *args:
    @uv run {{ args }}

# Bump the dev version
[group("project")]
bump-dev:
    uv version --bump dev

# Build the package
[group("project")]
build:
    uv build

# Publish the package to PyPI
[group("project")]
publish:
    just python-run dotenv --file pypi.env run uv publish dist/*

# Run pre-commit with custom arguments
[group("lint")]
pre-commit *args:
    just python-run pre-commit {{ args }}

# Run all checks (pre-commit hooks, lint, typecheck)
[group("lint")]
lint:
    @# Retry once: hooks that auto-fix files (ruff, trailing-whitespace, etc.) fail on first run; second run verifies fixes.
    just pre-commit run --all-files || just pre-commit run --all-files

# Run tests with pytest
[group("project")]
test *args:
    just python-run pytest {{ args }}

# Run lint and tests
[group("project")]
check: lint test
