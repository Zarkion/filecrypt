# Security policy

filecrypt is a small, single-maintainer project, and most of its code was
written with an AI coding assistant. It has had no independent security audit.
The reviews it has had were done by the same AI that wrote the code, so they
are not independent and should not be taken as assurance (see
[Known limitations](docs/threat-model.md#known-limitations)). Read the
[threat model](docs/threat-model.md) before you rely on it for anything
important.

## Reporting a vulnerability

Please report security problems privately, not in a public issue or pull
request.

1. Go to the repository's **Security** tab on GitHub.
2. Choose **Report a vulnerability** (GitHub private vulnerability reporting).
3. Describe the problem, the version or commit you tested, and how to
   reproduce it. A sample `.fcx` file or a failing test is very welcome. Never
   send real keys, passphrases or private files.

You should get an acknowledgement within 7 days. Once a fix is ready, it will
be released and the advisory published, with credit to you unless you would
rather stay anonymous. Please give the maintainer a reasonable chance to ship
a fix (normally up to 90 days) before disclosing publicly.

Useful things to report include:

* anything that lets someone read or undetectably change the contents of an
  `.fcx` file without the key or passphrase;
* a way to make filecrypt accept a modified, truncated or reordered file;
* a crafted `.fcx` file that makes filecrypt use far more memory or time than
  the documented caps allow, or crash in a way that leaks data;
* secrets showing up in error messages, logs, temp files or files with the
  wrong permissions;
* a key source or plugin-loading path that runs code the user didn't install.

Things listed under "What filecrypt does not protect" in the threat model,
such as visible file sizes, are known and by design, but tell us if you think
one of them is worse than described.

## Supported versions

filecrypt has not had a 1.0 release yet. Security fixes go to the latest
release and the `main` branch only.

| Version | Supported |
| --- | --- |
| `main` | yes |
| 0.1.x (latest) | yes |
| anything older | no, please upgrade |

Upgrading is always safe for your existing files: every release can decrypt
every `.fcx` version 1 file ever written. See the
[compatibility promise](docs/compatibility.md).
