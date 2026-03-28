# Code Style

## Rules

### MUST: Use explicit keyword arguments in all function and method calls

All parameter names MUST be explicitly specified in every function and method call across the project — both in source
code and tests. This applies to project code, external libraries, and standard library calls.

Positional usage is acceptable only for built-in primitives (`str`, `int`, `list`, `len`, `range`, `isinstance`, `cast`,
etc.), `NewType` constructors, no-argument calls, dictionary `.get()`/`.pop()`, and CPython positional-only parameters.

### MUST: Use type annotations on all functions, methods, and variables

All function/method signatures MUST have full type annotations (parameters and return types). Variables MUST be
annotated when the type is not obvious from the assignment. This applies to source code and tests.

Annotations may be omitted for loop and comprehension variables, and for variables with unambiguously clear literal
assignments.

All code MUST pass `mypy --strict`.

### MUST: Use `enum.auto()` for all `StrEnum` members

All `StrEnum` members MUST use `auto()` instead of explicit string values.
