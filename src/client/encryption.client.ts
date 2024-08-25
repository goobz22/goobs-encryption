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
import { GlobalConfig } from '../types';
import { ClientLogger } from 'goobs-testing';

const isBrowser = typeof window !== 'undefined' && 'crypto' in window;

interface EncryptedData<T> {
  encryptedValue: T;
  iv: Buffer;
  salt: Buffer;
  authTag: Buffer;
}

export const ClientEncryptionModule = {
  encryptionPassword: '',
  globalConfig: {} as GlobalConfig,
  cryptoImpl: {} as CryptoImplementation,

  initialize(encryptionPassword: string, globalConfig: GlobalConfig): void {
    this.encryptionPassword = encryptionPassword;
    this.globalConfig = globalConfig;
    this.cryptoImpl = isBrowser ? new BrowserCrypto() : new NodeCrypto();
    ClientLogger.initializeLogger(globalConfig);
    ClientLogger.info('ClientEncryptionModule initialized', {
      encryptionPassword: '[REDACTED]',
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

  encrypt<T>(value: T, callback: (result: EncryptedData<T>) => void): void {
    ClientLogger.info('Starting encryption process', {
      valueType: typeof value,
    });

    const startTime: number | [number, number] = isBrowser ? performance.now() : process.hrtime();
    const iv = this.getRandomValues(new Uint8Array(12));
    const salt = this.getRandomValues(new Uint8Array(16));

    const valueString = JSON.stringify(value);
    if (valueString.length === 0) {
      ClientLogger.debug('Handling empty string case in encryption');
      callback({
        encryptedValue: value,
        iv: Buffer.from(iv),
        salt: Buffer.from(salt),
        authTag: Buffer.alloc(16),
      });
      return;
    }

    this.cryptoImpl.deriveKey(this.encryptionPassword, salt, (key) => {
      this.cryptoImpl.encrypt(key, iv, Buffer.from(valueString), ({ encrypted, authTag }) => {
        const endTime: number | [number, number] = isBrowser
          ? performance.now()
          : process.hrtime(startTime as [number, number]);
        const totalTime = isBrowser
          ? (endTime as number) - (startTime as number)
          : ((endTime as [number, number])[0] * 1e9 + (endTime as [number, number])[1]) / 1e6;

        ClientLogger.info('Encryption process completed successfully', {
          totalTime: `${totalTime.toFixed(2)}ms`,
          inputLength: valueString.length,
          encryptedLength: encrypted.length,
          ivLength: iv.length,
          saltLength: salt.length,
          authTagLength: authTag.length,
        });

        callback({
          encryptedValue: encrypted as unknown as T,
          iv: Buffer.from(iv),
          salt: Buffer.from(salt),
          authTag: Buffer.from(authTag),
        });
      });
    });
  },

  decrypt<T>(encryptedData: EncryptedData<T>, callback: (result: T | null) => void): void {
    ClientLogger.info('Starting decryption process', {
      encryptedDataLength: (encryptedData.encryptedValue as unknown as Buffer).length,
      ivLength: encryptedData.iv.length,
      saltLength: encryptedData.salt.length,
      authTagLength: encryptedData.authTag.length,
    });

    const startTime: number | [number, number] = isBrowser ? performance.now() : process.hrtime();
    const { iv, salt, encryptedValue, authTag } = encryptedData;

    if ((encryptedValue as unknown as Buffer).length === 0) {
      ClientLogger.debug('Handling empty string case in decryption');
      callback(null);
      return;
    }

    this.cryptoImpl.deriveKey(this.encryptionPassword, salt, (key) => {
      this.cryptoImpl.decrypt(key, iv, encryptedValue as unknown as Buffer, authTag, (decrypted) => {
        const endTime: number | [number, number] = isBrowser
          ? performance.now()
          : process.hrtime(startTime as [number, number]);
        const totalTime = isBrowser
          ? (endTime as number) - (startTime as number)
          : ((endTime as [number, number])[0] * 1e9 + (endTime as [number, number])[1]) / 1e6;

        if (decrypted === null) {
          ClientLogger.error('Decryption error', {
            totalTime: `${totalTime.toFixed(2)}ms`,
            encryptedDataLength: (encryptedValue as unknown as Buffer).length,
            ivLength: iv.length,
            saltLength: salt.length,
            authTagLength: authTag.length,
          });
          callback(null);
        } else {
          ClientLogger.info('Decryption process completed successfully', {
            totalTime: `${totalTime.toFixed(2)}ms`,
            encryptedDataLength: (encryptedValue as unknown as Buffer).length,
            decryptedDataLength: decrypted.length,
          });
          try {
            const decryptedValue = JSON.parse(decrypted.toString()) as T;
            callback(decryptedValue);
          } catch (error) {
            ClientLogger.error('Error parsing decrypted data', {
              error: error instanceof Error ? error.message : String(error),
              stack: error instanceof Error ? error.stack : undefined,
            });
            callback(null);
          }
        }
      });
    });
  },

  updateConfig(newEncryptionPassword: string, newGlobalConfig: GlobalConfig): void {
    ClientLogger.info('Updating ClientEncryptionModule configuration', {
      oldEncryptionPassword: '[REDACTED]',
      newEncryptionPassword: '[REDACTED]',
      oldGlobalConfig: { ...this.globalConfig, encryptionPassword: '[REDACTED]' },
      newGlobalConfig: { ...newGlobalConfig, encryptionPassword: '[REDACTED]' },
    });
    this.encryptionPassword = newEncryptionPassword;
    this.globalConfig = newGlobalConfig;
    ClientLogger.initializeLogger(newGlobalConfig);
  },
};

interface CryptoImplementation {
  deriveKey(password: string, salt: Uint8Array, callback: (key: CipherKey) => void): void;
  encrypt(
    key: CipherKey,
    iv: Uint8Array,
    data: Buffer,
    callback: (result: { encrypted: Buffer; authTag: Buffer }) => void,
  ): void;
  decrypt(
    key: CipherKey,
    iv: Buffer,
    data: Buffer,
    authTag: Buffer,
    callback: (result: Buffer | null) => void,
  ): void;
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
    data: Buffer,
    callback: (result: { encrypted: Buffer; authTag: Buffer }) => void,
  ): void {
    ClientLogger.debug('Encrypting data in the browser', {
      dataLength: data.length,
      ivLength: iv.length,
    });
    const startTime = performance.now();
    window.crypto.subtle
      .encrypt({ name: 'AES-GCM', iv: iv }, key as unknown as CryptoKey, data)
      .then((encrypted) => {
        const encryptedContent = Buffer.from(encrypted.slice(0, -16));
        const authTag = Buffer.from(encrypted.slice(-16));
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
    iv: Buffer,
    data: Buffer,
    authTag: Buffer,
    callback: (result: Buffer | null) => void,
  ): void {
    ClientLogger.debug('Decrypting data in the browser', {
      dataLength: data.length,
      ivLength: iv.length,
      authTagLength: authTag.length,
    });

    const startTime = performance.now();
    const combinedData = Buffer.concat([data, authTag]);

    window.crypto.subtle
      .decrypt({ name: 'AES-GCM', iv: iv }, key as unknown as CryptoKey, combinedData)
      .then((decrypted) => {
        const endTime = performance.now();
        ClientLogger.debug('Data decrypted successfully in the browser', {
          decryptionTime: `${(endTime - startTime).toFixed(2)}ms`,
          decryptedLength: decrypted.byteLength,
        });
        callback(Buffer.from(decrypted));
      })
      .catch((error: Error) => {
        ClientLogger.error('Error decrypting data in the browser', {
          error: error.message,
          stack: error.stack,
        });
        callback(null);
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
      callback(derivedKey);
    });
  }

  encrypt(
    key: CipherKey,
    iv: Uint8Array,
    data: Buffer,
    callback: (result: { encrypted: Buffer; authTag: Buffer }) => void,
  ): void {
    ClientLogger.debug('Encrypting data in Node.js', {
      dataLength: data.length,
      ivLength: iv.length,
    });

    const startTime = process.hrtime();
    const cipher: CipherGCM = createCipheriv('aes-256-gcm', key, iv as BinaryLike) as CipherGCM;
    const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
    const authTag = cipher.getAuthTag();
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
    iv: Buffer,
    data: Buffer,
    authTag: Buffer,
    callback: (result: Buffer | null) => void,
  ): void {
    ClientLogger.debug('Decrypting data in Node.js', {
      dataLength: data.length,
      ivLength: iv.length,
      authTagLength: authTag.length,
    });

    const startTime = process.hrtime();
    const decipher: Decipher = createDecipheriv('aes-256-gcm', key, iv);
    (decipher as DecipherGCM).setAuthTag(authTag);

    try {
      const decrypted = Buffer.concat([decipher.update(data), decipher.final()]);
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
}

// Add an unhandled rejection handler for Node.js environments
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

export default ClientEncryptionModule;