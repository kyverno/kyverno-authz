---
title: "kyverno-authz completion bash"
slug: "kyverno-authz_completion_bash"
description: "CLI reference for kyverno-authz completion bash"
---

## kyverno-authz completion bash

Generate the autocompletion script for bash

### Synopsis

Generate the autocompletion script for the bash shell.

This script depends on the 'bash-completion' package.
If it is not installed already, you can install it via your OS's package manager.

To load completions in your current shell session:

	source <(kyverno-authz completion bash)

To load completions for every new session, execute once:

#### Linux:

	kyverno-authz completion bash > /etc/bash_completion.d/kyverno-authz

#### macOS:

	kyverno-authz completion bash > $(brew --prefix)/etc/bash_completion.d/kyverno-authz

You will need to start a new shell for this setup to take effect.


```
kyverno-authz completion bash
```

### Options

```
  -h, --help              help for bash
      --no-descriptions   disable completion descriptions
```

### SEE ALSO

* [kyverno-authz completion](kyverno-authz_completion.md)	 - Generate the autocompletion script for the specified shell

