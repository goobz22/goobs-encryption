# goobs-encryption

A robust, versatile encryption library for JavaScript/TypeScript applications, supporting both client-side (browser) and server-side (Node.js) environments.

## Table of Contents

1. [Features](#features)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [Detailed Usage Guide](#detailed-usage-guide)
   - [Configuration](#configuration)
   - [Client-side Usage](#client-side-usage)
   - [Server-side Usage](#server-side-usage)
   - [Handling Encrypted Data](#handling-encrypted-data)
   - [Key Rotation](#key-rotation)
5. [API Reference](#api-reference)
6. [Security Best Practices](#security-best-practices)
7. [Troubleshooting](#troubleshooting)
8. [Contributing](#contributing)
9. [License](#license)

## Features

- AES-256-GCM encryption for high security
- PBKDF2 key derivation to enhance password security
- Cross-environment support (works in both browsers and Node.js)
- TypeScript support for improved developer experience
- Configurable logging for easy debugging
- Automatic key rotation to maintain security over time
- Promise-based API for browser environments
- Callback-based API for Node.js environments

## Installation

Install the package using npm:

```bash
npm install goobs-encryption
```

Or using yarn:

```bash
yarn add goobs-encryption
```

## Quick Start

Here's a basic example to get you started:

```typescript
import { ClientEncryptionModule, ServerEncryptionModule } from 'goobs-encryption';
import type { EncryptionConfig, GlobalConfig } from 'goobs-encryption';

// Configuration
const config: EncryptionConfig = {
  algorithm: 'aes-256-gcm',
  encryptionPassword: 'your-secure-password',
  keyCheckIntervalMs: 3600000, // 1 hour
  keyRotationIntervalMs: 86400000, // 24 hours
};

const globalConfig: GlobalConfig = {
  loggingEnabled: true,
  logLevel: 'info',
  logDirectory: '/path/to/logs',
};

// Initialize (use appropriate module based on your environment)
ClientEncryptionModule.initialize(config, globalConfig);
// or
await ServerEncryptionModule.initialize(config, globalConfig);

// Encrypt data
const dataToEncrypt = new TextEncoder().encode('Secret message');

// Client-side encryption
ClientEncryptionModule.encrypt(dataToEncrypt, (encryptedValue) => {
  console.log('Encrypted:', encryptedValue);

  // Decrypt data
  ClientEncryptionModule.decrypt(encryptedValue, (decryptedData) => {
    if (decryptedData) {
      console.log('Decrypted:', new TextDecoder().decode(decryptedData));
    }
  });
});

// Server-side encryption
try {
  const encryptedValue = await ServerEncryptionModule.encrypt(dataToEncrypt);
  console.log('Encrypted:', encryptedValue);

  const decryptedData = await ServerEncryptionModule.decrypt(encryptedValue);
  console.log('Decrypted:', new TextDecoder().decode(decryptedData));
} catch (error) {
  console.error('Encryption error:', error);
}
```

## Detailed Usage Guide

### Configuration

Before using the encryption modules, you need to set up the configuration:

```typescript
import type { EncryptionConfig, GlobalConfig } from 'goobs-encryption';

const encryptionConfig: EncryptionConfig = {
  algorithm: 'aes-256-gcm', // The encryption algorithm to use
  encryptionPassword: 'your-very-secure-password', // A strong password for encryption
  keyCheckIntervalMs: 3600000, // How often to check if the key needs rotation (1 hour)
  keyRotationIntervalMs: 86400000, // How often to rotate the key (24 hours)
};

const globalConfig: GlobalConfig = {
  loggingEnabled: true, // Enable or disable logging
  logLevel: 'info', // Log level: 'error', 'warn', 'info', 'http', 'verbose', or 'debug'
  logDirectory: '/path/to/logs', // Directory for log files (server-side only)
};
```

### Client-side Usage

In a browser environment:

```typescript
import { ClientEncryptionModule } from 'goobs-encryption';

// Initialize the module
ClientEncryptionModule.initialize(encryptionConfig, globalConfig);

// Encrypt data
const dataToEncrypt = new TextEncoder().encode('Secret message');
ClientEncryptionModule.encrypt(dataToEncrypt, (encryptedValue) => {
  console.log('Encrypted data:', encryptedValue);

  // Decrypt data
  ClientEncryptionModule.decrypt(encryptedValue, (decryptedData) => {
    if (decryptedData) {
      console.log('Decrypted message:', new TextDecoder().decode(decryptedData));
    } else {
      console.error('Decryption failed');
    }
  });
});
```

### Server-side Usage

In a Node.js environment:

```typescript
import { ServerEncryptionModule } from 'goobs-encryption';

// Initialize the module
await ServerEncryptionModule.initialize(encryptionConfig, globalConfig);

// Encrypt data
const dataToEncrypt = Buffer.from('Secret message');
try {
  const encryptedValue = await ServerEncryptionModule.encrypt(dataToEncrypt);
  console.log('Encrypted data:', encryptedValue);

  // Decrypt data
  const decryptedData = await ServerEncryptionModule.decrypt(encryptedValue);
  console.log('Decrypted message:', decryptedData.toString());
} catch (error) {
  console.error('Encryption/Decryption error:', error);
}
```

### Handling Encrypted Data

The `EncryptedValue` object returned by the encryption process contains several properties:

```typescript
interface EncryptedValue {
  type: 'encrypted';
  encryptedData: Uint8Array; // The encrypted data
  iv: Uint8Array; // Initialization vector
  salt: Uint8Array; // Salt used for key derivation
  authTag: Uint8Array; // Authentication tag
  encryptionKey: Uint8Array; // Derived encryption key
}
```

You can store or transmit this entire object and use it later for decryption.

### Key Rotation

Key rotation is handled automatically based on the `keyRotationIntervalMs` setting. You don't need to manually rotate keys, but you can force a key rotation by updating the configuration:

```typescript
const newConfig: EncryptionConfig = {
  ...encryptionConfig,
  encryptionPassword: 'new-secure-password',
};

// Client-side
ClientEncryptionModule.updateConfig(newConfig, globalConfig);

// Server-side
await ServerEncryptionModule.updateConfig(newConfig, globalConfig);
```

## API Reference

### ClientEncryptionModule

- `initialize(config: EncryptionConfig, globalConfig: GlobalConfig): void`
- `encrypt(value: Uint8Array, callback: (result: EncryptedValue) => void): void`
- `decrypt(encryptedValue: EncryptedValue, callback: (result: Uint8Array | null) => void): void`
- `updateConfig(newConfig: EncryptionConfig, newGlobalConfig: GlobalConfig): void`

### ServerEncryptionModule

- `initialize(config: EncryptionConfig, globalConfig: GlobalConfig): Promise<void>`
- `encrypt(value: Uint8Array): Promise<EncryptedValue>`
- `decrypt(encryptedValue: EncryptedValue): Promise<Uint8Array>`
- `updateConfig(newConfig: EncryptionConfig, newGlobalConfig: GlobalConfig): Promise<void>`

## Security Best Practices

1. **Strong Passwords**: Use a strong, unique password for `encryptionPassword`. Consider using a password generator.

2. **Secure Storage**: Never hard-code or commit your `encryptionPassword` to version control. Use environment variables or secure key management systems.

3. **Regular Key Rotation**: Set appropriate values for `keyCheckIntervalMs` and `keyRotationIntervalMs` to ensure regular key rotation.

4. **Secure Communication**: When transmitting encrypted data, always use secure channels (e.g., HTTPS).

5. **Input Validation**: Always validate and sanitize input before encryption to prevent potential attacks.

6. **Error Handling**: Implement proper error handling to avoid leaking sensitive information through error messages.

7. **Logging**: Be cautious about what you log. Never log decrypted data or encryption keys.

## Troubleshooting

### Common Issues

1. **Decryption Fails**:

   - Ensure you're using the same encryption password and configuration for encryption and decryption.
   - Check if the `EncryptedValue` object is complete and not corrupted.

2. **Performance Issues**:

   - If encryption/decryption is slow, consider adjusting the `keyCheckIntervalMs` and `keyRotationIntervalMs` values.
   - For large data sets, consider encrypting in chunks.

3. **Key Rotation Problems**:
   - If you're having issues after key rotation, ensure all parts of your application are using the updated configuration.

### Debugging

Enable detailed logging by setting the `logLevel` to `'debug'` in the `GlobalConfig`:

```typescript
const globalConfig: GlobalConfig = {
  loggingEnabled: true,
  logLevel: 'debug',
  logDirectory: '/path/to/logs',
};
```

This will provide more detailed logs to help identify issues.

## Contributing

We welcome contributions to goobs-encryption! Please reach out to Matthew Goluba if you would like too.

Please make sure to update tests as appropriate and adhere to the existing coding style.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

If you encounter any issues or have questions, please file an issue on the GitHub issue tracker.

---

We hope this guide helps you get started with goobs-encryption. For more detailed information about the cryptographic principles used in this library, please refer to the [Cryptography Concepts](CRYPTO_CONCEPTS.md) document.

Remember, while this library aims to make encryption easier, it's crucial to understand the underlying principles and potential security implications when dealing with sensitive data. Always consult with a security expert when implementing encryption in production systems.

## Contact

For questions or feedback:

- GitHub Issues: https://github.com/goobz22/goobs-cache/issues
- Email: mkgoluba@technologiesunlimited.net
