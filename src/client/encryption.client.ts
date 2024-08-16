'use client';

import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  CipherKey,
  BinaryLike,
  CipherGCM,
  DecipherGCM,
  Decipher,
  pbkdf2,
} from 'crypto';
import { EncryptionConfig, EncryptedValue, GlobalConfig } from '../types';
import { ClientLogger } from 'goobs-testing';

const isBrowser = typeof window !== 'undefined' && 'crypto' in window;

export const ClientEncryptionModule = {
  config: {} as EncryptionConfig,
  globalConfig: {} as GlobalConfig,
  cryptoImpl: {} as CryptoImplementation,

  initialize(config: EncryptionConfig, globalConfig: GlobalConfig): void {
    this.config = config;
    this.globalConfig = globalConfig;
    this.cryptoImpl = isBrowser ? new BrowserCrypto() : new NodeCrypto();
    ClientLogger.initializeLogger(globalConfig);
    ClientLogger.info('ClientEncryptionModule initialized', {
      config: { ...config, encryptionPassword: '[REDACTED]' },
      globalConfig: { ...globalConfig, encryptionPassword: '[REDACTED]' },
      environment: isBrowser ? 'Browser' : 'Node.js',
      cryptoImplementation: isBrowser ? 'BrowserCrypto' : 'NodeCrypto',
    });
  },

  getRandomValues(array: Uint8Array): Uint8Array {
    ClientLogger.debug('Generating random values', {
      length: array.length,
      environment: isBrowser ? 'browser' : 'node',
    });
    if (isBrowser) {
      return window.crypto.getRandomValues(array);
    } else {
      return Uint8Array.from(randomBytes(array.length));
    }
  },

  encrypt(value: Uint8Array, callback: (result: EncryptedValue) => void): void {
    ClientLogger.info('Starting encryption process', {
      valueLength: value.length,
      algorithm: this.config.algorithm,
    });

    const startTime: number | [number, number] = isBrowser ? performance.now() : process.hrtime();
    const iv = this.getRandomValues(new Uint8Array(12));
    const salt = this.getRandomValues(new Uint8Array(16));

    if (value.length === 0) {
      ClientLogger.debug('Handling empty string case in encryption');
      callback({
        type: 'encrypted',
        encryptedData: new Uint8Array(0),
        iv: iv,
        salt: salt,
        authTag: new Uint8Array(16),
        encryptionKey: new Uint8Array(32),
      });
      return;
    }

    this.cryptoImpl.deriveKey(this.config.encryptionPassword, salt, (key) => {
      this.cryptoImpl.encrypt(key, iv, value, ({ encrypted, authTag }) => {
        this.cryptoImpl.exportKey(key, (exportedKey) => {
          const endTime: number | [number, number] = isBrowser
            ? performance.now()
            : process.hrtime(startTime as [number, number]);
          const totalTime = isBrowser
            ? (endTime as number) - (startTime as number)
            : ((endTime as [number, number])[0] * 1e9 + (endTime as [number, number])[1]) / 1e6;

          ClientLogger.info('Encryption process completed successfully', {
            totalTime: `${totalTime.toFixed(2)}ms`,
            inputLength: value.length,
            encryptedLength: encrypted.length,
            ivLength: iv.length,
            saltLength: salt.length,
            authTagLength: authTag.length,
            exportedKeyLength: exportedKey.length,
          });

          callback({
            type: 'encrypted',
            encryptedData: encrypted,
            iv: iv,
            salt: salt,
            authTag: authTag,
            encryptionKey: exportedKey,
          });
        });
      });
    });
  },

  decrypt(encryptedValue: EncryptedValue, callback: (result: Uint8Array | null) => void): void {
    ClientLogger.info('Starting decryption process', {
      encryptedDataLength: encryptedValue.encryptedData.length,
      algorithm: this.config.algorithm,
      ivLength: encryptedValue.iv.length,
      saltLength: encryptedValue.salt.length,
      authTagLength: encryptedValue.authTag.length,
    });

    const startTime: number | [number, number] = isBrowser ? performance.now() : process.hrtime();
    const { iv, salt, encryptedData, authTag } = encryptedValue;

    if (encryptedData.length === 0) {
      ClientLogger.debug('Handling empty string case in decryption');
      callback(new Uint8Array(0));
      return;
    }

    this.cryptoImpl.deriveKey(this.config.encryptionPassword, salt, (key) => {
      this.cryptoImpl.decrypt(key, iv, encryptedData, authTag, (decrypted) => {
        const endTime: number | [number, number] = isBrowser
          ? performance.now()
          : process.hrtime(startTime as [number, number]);
        const totalTime = isBrowser
          ? (endTime as number) - (startTime as number)
          : ((endTime as [number, number])[0] * 1e9 + (endTime as [number, number])[1]) / 1e6;

        if (decrypted === null) {
          ClientLogger.error('Decryption error', {
            totalTime: `${totalTime.toFixed(2)}ms`,
            encryptedDataLength: encryptedData.length,
            ivLength: iv.length,
            saltLength: salt.length,
            authTagLength: authTag.length,
          });
        } else {
          ClientLogger.info('Decryption process completed successfully', {
            totalTime: `${totalTime.toFixed(2)}ms`,
            encryptedDataLength: encryptedData.length,
            decryptedDataLength: decrypted.length,
          });
        }
        callback(decrypted);
      });
    });
  },

  updateConfig(newConfig: EncryptionConfig, newGlobalConfig: GlobalConfig): void {
    ClientLogger.info('Updating ClientEncryptionModule configuration', {
      oldConfig: { ...this.config, encryptionPassword: '[REDACTED]' },
      newConfig: { ...newConfig, encryptionPassword: '[REDACTED]' },
      oldGlobalConfig: { ...this.globalConfig, encryptionPassword: '[REDACTED]' },
      newGlobalConfig: { ...newGlobalConfig, encryptionPassword: '[REDACTED]' },
    });
    this.config = newConfig;
    this.globalConfig = newGlobalConfig;
    ClientLogger.initializeLogger(newGlobalConfig);
  },
};

interface CryptoImplementation {
  deriveKey(password: string, salt: Uint8Array, callback: (key: CipherKey) => void): void;
  encrypt(
    key: CipherKey,
    iv: Uint8Array,
    data: Uint8Array,
    callback: (result: { encrypted: Uint8Array; authTag: Uint8Array }) => void,
  ): void;
  decrypt(
    key: CipherKey,
    iv: Uint8Array,
    data: Uint8Array,
    authTag: Uint8Array,
    callback: (result: Uint8Array | null) => void,
  ): void;
  exportKey(key: CipherKey, callback: (result: Uint8Array) => void): void;
}

class BrowserCrypto implements CryptoImplementation {
  deriveKey(password: string, salt: Uint8Array, callback: (key: CipherKey) => void): void {
    ClientLogger.debug('Deriving key in the browser', {
      passwordLength: password.length,
      saltLength: salt.length,
    });
    const startTime = performance.now();
    const enc = new TextEncoder();
    window.crypto.subtle
      .importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, [
        'deriveBits',
        'deriveKey',
      ])
      .then((keyMaterial) =>
        window.crypto.subtle.deriveKey(
          {
            name: 'PBKDF2',
            salt: salt,
            iterations: 100000,
            hash: 'SHA-256',
          },
          keyMaterial,
          { name: 'AES-GCM', length: 256 },
          true,
          ['encrypt', 'decrypt'],
        ),
      )
      .then((key) => {
        const endTime = performance.now();
        ClientLogger.debug('Key derived successfully in the browser', {
          derivationTime: `${(endTime - startTime).toFixed(2)}ms`,
        });
        callback(key as unknown as CipherKey);
      })
      .catch((error: Error) => {
        ClientLogger.error('Error deriving key in the browser', {
          error: error.message,
          stack: error.stack,
        });
      });
  }

  encrypt(
    key: CipherKey,
    iv: Uint8Array,
    data: Uint8Array,
    callback: (result: { encrypted: Uint8Array; authTag: Uint8Array }) => void,
  ): void {
    ClientLogger.debug('Encrypting data in the browser', {
      dataLength: data.length,
      ivLength: iv.length,
    });
    const startTime = performance.now();
    window.crypto.subtle
      .encrypt({ name: 'AES-GCM', iv: iv }, key as unknown as CryptoKey, data)
      .then((encrypted) => {
        const encryptedContent = new Uint8Array(encrypted, 0, encrypted.byteLength - 16);
        const authTag = new Uint8Array(encrypted, encrypted.byteLength - 16);
        const endTime = performance.now();
        ClientLogger.debug('Data encrypted successfully in the browser', {
          encryptionTime: `${(endTime - startTime).toFixed(2)}ms`,
          encryptedLength: encryptedContent.length,
          authTagLength: authTag.length,
        });
        callback({
          encrypted: encryptedContent,
          authTag: authTag,
        });
      })
      .catch((error: Error) => {
        ClientLogger.error('Error encrypting data in the browser', {
          error: error.message,
          stack: error.stack,
        });
      });
  }

  decrypt(
    key: CipherKey,
    iv: Uint8Array,
    data: Uint8Array,
    authTag: Uint8Array,
    callback: (result: Uint8Array | null) => void,
  ): void {
    ClientLogger.debug('Decrypting data in the browser', {
      dataLength: data.length,
      ivLength: iv.length,
      authTagLength: authTag.length,
    });

    const startTime = performance.now();
    const combinedData = new Uint8Array(data.length + authTag.length);
    combinedData.set(data, 0);
    combinedData.set(authTag, data.length);

    window.crypto.subtle
      .decrypt({ name: 'AES-GCM', iv: iv }, key as unknown as CryptoKey, combinedData)
      .then((decrypted) => {
        const endTime = performance.now();
        ClientLogger.debug('Data decrypted successfully in the browser', {
          decryptionTime: `${(endTime - startTime).toFixed(2)}ms`,
          decryptedLength: decrypted.byteLength,
        });
        callback(new Uint8Array(decrypted));
      })
      .catch((error: Error) => {
        ClientLogger.error('Error decrypting data in the browser', {
          error: error.message,
          stack: error.stack,
        });
        callback(null);
      });
  }

  exportKey(key: CipherKey, callback: (result: Uint8Array) => void): void {
    ClientLogger.debug('Exporting key in the browser');

    const startTime = performance.now();
    window.crypto.subtle
      .exportKey('raw', key as unknown as CryptoKey)
      .then((exported) => {
        const endTime = performance.now();
        ClientLogger.debug('Key exported successfully in the browser', {
          exportTime: `${(endTime - startTime).toFixed(2)}ms`,
          exportedKeyLength: exported.byteLength,
        });
        callback(new Uint8Array(exported));
      })
      .catch((error: Error) => {
        ClientLogger.error('Error exporting key in the browser', {
          error: error.message,
          stack: error.stack,
        });
      });
  }
}

class NodeCrypto implements CryptoImplementation {
  deriveKey(password: string, salt: Uint8Array, callback: (key: CipherKey) => void): void {
    ClientLogger.debug('Deriving key in Node.js', {
      passwordLength: password.length,
      saltLength: salt.length,
    });

    const startTime = process.hrtime();
    pbkdf2(password, salt, 100000, 32, 'sha256', (err: Error | null, derivedKey: Buffer) => {
      if (err) {
        ClientLogger.error('Key derivation error in Node.js', {
          error: err.message,
          stack: err.stack,
        });
        throw err;
      }
      const endTime = process.hrtime(startTime);
      const derivationTime = (endTime[0] * 1e9 + endTime[1]) / 1e6;
      ClientLogger.debug('Key derived successfully in Node.js', {
        derivationTime: `${derivationTime.toFixed(2)}ms`,
        derivedKeyLength: derivedKey.length,
      });
      callback(derivedKey as unknown as CipherKey);
    });
  }

  encrypt(
    key: CipherKey,
    iv: Uint8Array,
    data: Uint8Array,
    callback: (result: { encrypted: Uint8Array; authTag: Uint8Array }) => void,
  ): void {
    ClientLogger.debug('Encrypting data in Node.js', {
      dataLength: data.length,
      ivLength: iv.length,
    });

    const startTime = process.hrtime();
    const cipher: CipherGCM = createCipheriv('aes-256-gcm', key, iv as BinaryLike) as CipherGCM;
    const encryptedChunks: Uint8Array[] = [];
    encryptedChunks.push(new Uint8Array(cipher.update(data)));
    encryptedChunks.push(new Uint8Array(cipher.final()));

    const encrypted = new Uint8Array(encryptedChunks.reduce((acc, chunk) => acc + chunk.length, 0));
    let offset = 0;
    for (const chunk of encryptedChunks) {
      encrypted.set(chunk, offset);
      offset += chunk.length;
    }

    const authTag = new Uint8Array(cipher.getAuthTag());
    const endTime = process.hrtime(startTime);
    const encryptionTime = (endTime[0] * 1e9 + endTime[1]) / 1e6;
    ClientLogger.debug('Data encrypted successfully in Node.js', {
      encryptionTime: `${encryptionTime.toFixed(2)}ms`,
      encryptedLength: encrypted.length,
      authTagLength: authTag.length,
    });
    callback({ encrypted, authTag });
  }

  decrypt(
    key: CipherKey,
    iv: Uint8Array,
    data: Uint8Array,
    authTag: Uint8Array,
    callback: (result: Uint8Array | null) => void,
  ): void {
    ClientLogger.debug('Decrypting data in Node.js', {
      dataLength: data.length,
      ivLength: iv.length,
      authTagLength: authTag.length,
    });

    const startTime = process.hrtime();
    const decipher: Decipher = createDecipheriv('aes-256-gcm', key, iv);
    (decipher as DecipherGCM).setAuthTag(authTag);

    const decryptedChunks: Uint8Array[] = [];

    try {
      decryptedChunks.push(new Uint8Array(decipher.update(data)));
      decryptedChunks.push(new Uint8Array(decipher.final()));
      const decrypted = new Uint8Array(
        decryptedChunks.reduce((acc, chunk) => acc + chunk.length, 0),
      );
      const endTime = process.hrtime(startTime);
      const decryptionTime = (endTime[0] * 1e9 + endTime[1]) / 1e6;
      ClientLogger.debug('Data decrypted successfully in Node.js', {
        decryptionTime: `${decryptionTime.toFixed(2)}ms`,
        decryptedLength: decrypted.length,
      });
      callback(decrypted);
    } catch (error) {
      ClientLogger.error('Error decrypting data in Node.js', {
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
      });
      callback(null);
    }
  }

  exportKey(key: CipherKey, callback: (result: Uint8Array) => void): void {
    ClientLogger.debug('Exporting key in Node.js');

    const startTime = process.hrtime();
    let exportedKey: Uint8Array;
    if (Buffer.isBuffer(key)) {
      exportedKey = new Uint8Array(key);
    } else if (typeof key === 'string') {
      exportedKey = new TextEncoder().encode(key);
    } else if (key instanceof Uint8Array) {
      exportedKey = key;
    } else {
      exportedKey = new Uint8Array(Buffer.from(key as ArrayBuffer));
    }
    const endTime = process.hrtime(startTime);
    const exportTime = (endTime[0] * 1e9 + endTime[1]) / 1e6;
    ClientLogger.debug('Key exported successfully in Node.js', {
      exportTime: `${exportTime.toFixed(2)}ms`,
      exportedKeyLength: exportedKey.length,
    });
    callback(exportedKey);
  }
}

// Add an unhandled rejection handler
if (typeof process !== 'undefined' && process.on) {
  process.on('unhandledRejection', (reason: unknown, promise: Promise<unknown>) => {
    ClientLogger.error('Unhandled Rejection at:', {
      promise,
      reason: reason instanceof Error ? reason.message : String(reason),
      stack: reason instanceof Error ? reason.stack : undefined,
    });
  });
}

// Add an unhandled rejection handler for browser environments
if (typeof window !== 'undefined') {
  window.addEventListener('unhandledrejection', (event: PromiseRejectionEvent) => {
    ClientLogger.error('Unhandled Rejection at:', {
      reason: event.reason instanceof Error ? event.reason.message : String(event.reason),
      stack: event.reason instanceof Error ? event.reason.stack : undefined,
    });
  });
}
