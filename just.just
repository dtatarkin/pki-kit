[default]
[doc("List all available recipes")]
[group("just")]
list-recipes:
    @just --list

[doc("Configure completion for the Bash shell")]
[group("just")]
[linux]
bash-completion:
    just --completions bash > ~/.bashrc.d/just.sh

[doc("Selecting Recipes to Run With an Interactive Chooser")]
[group("just")]
fzf:
    @just --choose --chooser fzf

[doc("Format justfiles")]
[group("just")]
format-justfiles:
    just --fmt --unstable

[doc("Print system architecture info")]
[group("just")]
system-info:
    @echo "This is an {{ arch() }} machine".

[doc("Print path to the just executable")]
[group("just")]
executable:
    @echo The executable is at: {{ just_executable() }}
