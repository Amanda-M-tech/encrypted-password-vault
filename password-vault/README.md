# Encrypted Password Vault (Java)

A command-line password manager that stores logins in an AES-256 encrypted file, protected by a master password.
Built as a cybersecurity project after completing the Cisco *Introduction to Cybersecurity* course and the TryHackMe *Pre-Security* path.

## Security concepts used
| Concept | How it's used |
|---|---|
| **Key derivation (PBKDF2-HMAC-SHA256)** | Master password + random salt -> 256-bit key, 210,000 iterations to slow brute-force attacks |
| **Salting** | A unique random 16-byte salt per vault defeats rainbow tables |
| **AES-256-GCM** | Encrypts the vault and authenticates it, so a wrong password or a modified file is detected |
| **Random IV** | A fresh 12-byte IV on every save |
| **SecureRandom** | Used for salts, IVs and the password generator |
| **Lockout** | 3 wrong master-password attempts and the program exits |

The master password is never stored, not even as a hash. A wrong password produces a wrong key, and the GCM authentication check fails.

## Features
- Create a master password on first run
- Add, view and delete entries
- Built-in random password generator
- Vault file (`vault.dat`) is unreadable without the master password

## Run it
Requires JDK 11 or newer.

```bash
javac -d out src/*.java
java -cp out Main
```

Run from a real terminal so the master password is hidden while typing (IDE consoles show it).

## Project structure
```
src/
  Main.java          # menu / user interface
  VaultManager.java  # vault file handling, add/delete, password generator
  CryptoUtil.java    # PBKDF2 key derivation + AES-GCM encryption
  Entry.java         # one saved login
```

## Limitations and future improvements
- Passwords are shown in plain text on screen when viewed
- Lockout is per run (restarting resets the counter)
- Ideas: GUI, clipboard auto-clear, two-factor authentication, password strength checker

## Disclaimer
Educational project. For real-world use, choose an audited password manager.
