# Agents

## Code Style

Follow all rules in [docs/code_style.md](docs/code_style.md).

## Tool Usage

MUST use `just` commands instead of direct tool invocations if a just command exists.
Never call `uv`, `pytest`, `pre-commit`, or other project tools directly. Use the corresponding `just` recipe.
Run `just lint` at the end of every task.
