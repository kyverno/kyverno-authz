---
title: "kyverno-authz completion zsh"
slug: "kyverno-authz_completion_zsh"
description: "CLI reference for kyverno-authz completion zsh"
---

## kyverno-authz completion zsh

Generate the autocompletion script for zsh

### Synopsis

Generate the autocompletion script for the zsh shell.

If shell completion is not already enabled in your environment you will need
to enable it.  You can execute the following once:

	echo "autoload -U compinit; compinit" >> ~/.zshrc

To load completions in your current shell session:

	source <(kyverno-authz completion zsh)

To load completions for every new session, execute once:

#### Linux:

	kyverno-authz completion zsh > "${fpath[1]}/_kyverno-authz"

#### macOS:

	kyverno-authz completion zsh > $(brew --prefix)/share/zsh/site-functions/_kyverno-authz

You will need to start a new shell for this setup to take effect.


```
kyverno-authz completion zsh [flags]
```

### Options

```
  -h, --help              help for zsh
      --no-descriptions   disable completion descriptions
```

### SEE ALSO

* [kyverno-authz completion](kyverno-authz_completion.md)	 - Generate the autocompletion script for the specified shell

