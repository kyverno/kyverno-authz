# Shell Completion

Assuming the Kyverno Authz Server is installed locally, you can easily enable shell completion support for `Bash`, `Zsh`, `Fish`, and `PowerShell`.

Once set up, you can use the <Tab> key to auto-complete commands, flags, and even some arguments, which significantly improves the command-line experience.

## Generating Completion Scripts

You can generate shell completion scripts using the `kyverno-authz completion` command:

```bash
# For Bash
kyverno-authz completion bash

# For Zsh
kyverno-authz completion zsh

# For Fish
kyverno-authz completion fish

# For PowerShell
kyverno-authz completion powershell
```

## Setting Up Completion

### Bash

To enable completion in your current Bash session:

```bash
source <(kyverno-authz completion bash)
```

To enable completion for all sessions, add the above line to your `~/.bashrc` file:

```bash
echo 'source <(kyverno-authz completion bash)' >> ~/.bashrc
```

Alternatively, you can save the completion script to the bash-completion directory:

```bash
# On Linux
kyverno-authz completion bash > /etc/bash_completion.d/kyverno-authz

# On macOS with Homebrew
kyverno-authz completion bash > $(brew --prefix)/etc/bash_completion.d/kyverno-authz
```

### Zsh

To enable completion in your current Zsh session:

```bash
source <(kyverno-authz completion zsh)
```

To enable completion for all sessions, add the above line to your `~/.zshrc` file:

```bash
echo 'source <(kyverno-authz completion zsh)' >> ~/.zshrc
```

Alternatively, you can save the completion script to a directory in your `$fpath`:

```bash
# Create a directory for completions if it doesn't exist
mkdir -p ~/.zsh/completion
# Generate and save the completion script
kyverno-authz completion zsh > ~/.zsh/completion/_kyverno-authz

# Make sure the directory is in your fpath by adding to ~/.zshrc:
echo 'fpath=(~/.zsh/completion $fpath)' >> ~/.zshrc
echo 'autoload -U compinit; compinit' >> ~/.zshrc
```

### Fish

To enable completion in Fish:

```bash
kyverno-authz completion fish > ~/.config/fish/completions/kyverno-authz.fish
```

### PowerShell

To enable completion in PowerShell:

```powershell
kyverno-authz completion powershell | Out-String | Invoke-Expression
```

To make it persistent, add the above line to your PowerShell profile:

```powershell
# Find the profile path
echo $PROFILE

# Add the completion command to your profile
kyverno-authz completion powershell | Out-String | Out-File -Append $PROFILE
```

## Testing Completion

After setting up completion, you can test it by typing `kyverno-authz` followed by a space and pressing <Tab>. This should show available subcommands. You can also try typing partial commands like `kyverno-authz se` and then pressing <Tab>, which should complete to `kyverno-authz serve`.

## Detailed Reference

For more detailed information about each completion command, see the reference documentation:

- [Bash Completion](../reference/commands/kyverno-authz_completion_bash.md)
- [Fish Completion](../reference/commands/kyverno-authz_completion_fish.md)
- [PowerShell Completion](../reference/commands/kyverno-authz_completion_powershell.md)
- [Zsh Completion](../reference/commands/kyverno-authz_completion_zsh.md)
