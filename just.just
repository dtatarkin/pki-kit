# List all available recipes
[default]
[group("just")]
list-recipes:
    @just --list

# Configure completion for the Bash shell
[group("just")]
[linux]
bash-completion:
    just --completions bash > ~/.bashrc.d/just.sh

# Selecting Recipes to Run With an Interactive Chooser
[group("just")]
fzf:
    @just --choose --chooser fzf

# Format justfiles
[group("just")]
format-justfiles:
    just --fmt --unstable

# Print system architecture info
[group("just")]
system-info:
  @echo "This is an {{arch()}} machine".

# Print path to the just executable
[group("just")]
executable:
  @echo The executable is at: {{just_executable()}}
