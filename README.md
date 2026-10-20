[![Install](https://img.shields.io/badge/Install-Firefox_Addon-FF7139?style=for-the-badge&logo=firefox)](https://addons.mozilla.org/de/firefox/addon/linux-passkey-manager/)

# Linux Passkey Manager

A Firefox add-on that creates and stores passkeys (WebAuthn) locally, for systems like Linux where Firefox has no built-in passkey manager.

## Features

- Create and use passkeys on any website, without a hardware security key
- Passkeys are stored in the add-on's local storage (ECDSA P-256 / ES256)
- Sync across PCs through Firefox Sync or Nextcloud, encrypted with a password of your choice
- Export and import encrypted backup files
- Available in English, German and French

## How it works

The add-on replaces `navigator.credentials.create()` and `navigator.credentials.get()` on websites. When a site asks for a passkey, the add-on creates a key pair or signs the request in its background script and returns a regular `PublicKeyCredential` to the site. When you sign in on a site without a stored passkey, the browser's own flow is used.

The add-on identifies itself to websites with the AAGUID `e3379e58-a9a8-4cd7-a6f5-e754a22fe799`.

## Sync and backup

Open the add-on popup and choose **Backup & sync**.

- **Firefox Sync**: sign in to Firefox Sync on every PC and turn on "Add-ons" in its settings. Then enter the same sync password on every PC. Room for about 80 passkeys.
- **Nextcloud**: enter the Nextcloud address, user name, an app password and a sync password.
- **Backup file**: export your passkeys to a file encrypted with a password, and import it again later.

Backups and synced data contain your private keys. Keep the password safe.

## Development

Load the add-on temporarily: open `about:debugging#/runtime/this-firefox`, choose **Load Temporary Add-on** and select `manifest.json`.

Lint it like the CI does:

```sh
npx web-ext lint --source-dir . --ignore-files ".github/**" "generate-icons.js" "dist/**"
```

## License

[MIT](LICENSE)
