'use server';

import { promisify } from 'util';
import {
  randomBytes,
  scrypt,
  createCipheriv,
  createDecipheriv,
  CipherGCM,
  CipherCCM,
  DecipherGCM,
  DecipherCCM,
} from 'crypto';
import { EncryptionConfig, EncryptedValue, GlobalConfig } from '../types';
import { ServerLogger } from 'goobs-testing';

const randomBytesAsync = promisify(randomBytes);
const scryptAsync = promisify(scrypt);

const SUPPORTED_ALGORITHMS = ['aes-256-gcm', 'aes-256-ccm'];

export const ServerEncryptionModule = {
  config: {} as EncryptionConfig,
  globalConfig: {} as GlobalConfig,

  async initialize(config: EncryptionConfig, globalConfig: GlobalConfig): Promise<void> {
    this.config = config;
    this.globalConfig = globalConfig;
    await ServerLogger.info('ServerEncryptionModule initialized', {
      config: { ...config, encryptionPassword: '[REDACTED]' },
      globalConfig: { ...globalConfig, encryptionPassword: '[REDACTED]' },
      supportedAlgorithms: SUPPORTED_ALGORITHMS,
    });
    await ServerLogger.info('Server Encryption module initialized', {
      supportedAlgorithms: SUPPORTED_ALGORITHMS,
    });
  },

  async deriveKey(password: string, salt: Uint8Array): Promise<Buffer> {
    await ServerLogger.debug('Deriving encryption key', {
      passwordLength: password.length,
      saltLength: salt.length,
    });

    const startTime = process.hrtime();

    try {
      const key = (await scryptAsync(password, salt, 32)) as Buffer;

      const endTime = process.hrtime(startTime);
      const derivationTime = (endTime[0] * 1e9 + endTime[1]) / 1e6;

      await ServerLogger.debug('Encryption key derived successfully', {
        derivationTime: `${derivationTime.toFixed(2)}ms`,
        keyLength: key.length,
      });

      return key;
    } catch (error) {
      await ServerLogger.error('Error deriving encryption key', {
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
      });
      throw error;
    }
  },

  async encrypt(value: Uint8Array): Promise<EncryptedValue> {
    await ServerLogger.info('Starting encryption process', {
      valueLength: value.length,
      algorithm: this.config.algorithm,
    });

    const startTime = process.hrtime();

    if (!SUPPORTED_ALGORITHMS.includes(this.config.algorithm)) {
      const error = new Error(
        `Unsupported encryption algorithm: ${this.config.algorithm}. Supported algorithms are: ${SUPPORTED_ALGORITHMS.join(', ')}`,
      );
      await ServerLogger.error('Unsupported encryption algorithm', { error: error.message });
      throw error;
    }

    try {
      const iv = new Uint8Array(await randomBytesAsync(16));
      const salt = new Uint8Array(await randomBytesAsync(16));
      const key = new Uint8Array(await this.deriveKey(this.config.encryptionPassword, salt));

      let cipher: CipherGCM | CipherCCM;
      if (this.config.algorithm === 'aes-256-ccm') {
        cipher = createCipheriv(this.config.algorithm, key, iv) as CipherCCM;
      } else {
        cipher = createCipheriv(this.config.algorithm, key, iv) as CipherGCM;
      }

      await ServerLogger.debug('Cipher created', { algorithm: this.config.algorithm });

      const encryptedParts: Uint8Array[] = [];
      encryptedParts.push(new Uint8Array(cipher.update(value)));
      encryptedParts.push(new Uint8Array(cipher.final()));

      const encryptedData = new Uint8Array(
        encryptedParts.reduce((acc, curr) => acc + curr.length, 0),
      );
      let offset = 0;
      for (const part of encryptedParts) {
        encryptedData.set(part, offset);
        offset += part.length;
      }

      const authTag =
        'getAuthTag' in cipher ? new Uint8Array(cipher.getAuthTag()) : new Uint8Array(0);

      const endTime = process.hrtime(startTime);
      const encryptionTime = (endTime[0] * 1e9 + endTime[1]) / 1e6;

      await ServerLogger.info('Encryption process completed successfully', {
        encryptionTime: `${encryptionTime.toFixed(2)}ms`,
        inputLength: value.length,
        encryptedLength: encryptedData.length,
        ivLength: iv.length,
        saltLength: salt.length,
        authTagLength: authTag.length,
        keyLength: key.length,
      });

      return {
        type: 'encrypted',
        encryptedData,
        iv,
        salt,
        authTag,
        encryptionKey: key,
      };
    } catch (error) {
      await ServerLogger.error('Error during encryption process', {
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
      });
      throw error;
    }
  },

  async decrypt(encryptedValue: EncryptedValue): Promise<Uint8Array> {
    await ServerLogger.info('Starting decryption process', {
      encryptedDataLength: encryptedValue.encryptedData.length,
      algorithm: this.config.algorithm,
      ivLength: encryptedValue.iv.length,
      saltLength: encryptedValue.salt.length,
      authTagLength: encryptedValue.authTag.length,
    });

    const startTime = process.hrtime();

    if (!SUPPORTED_ALGORITHMS.includes(this.config.algorithm)) {
      const error = new Error(
        `Unsupported decryption algorithm: ${this.config.algorithm}. Supported algorithms are: ${SUPPORTED_ALGORITHMS.join(', ')}`,
      );
      await ServerLogger.error('Unsupported decryption algorithm', { error: error.message });
      throw error;
    }

    try {
      const { encryptedData, iv, salt, authTag } = encryptedValue;
      const key = new Uint8Array(await this.deriveKey(this.config.encryptionPassword, salt));

      await ServerLogger.debug('Decryption key derived', { keyLength: key.length });

      let decipher: DecipherGCM | DecipherCCM;
      if (this.config.algorithm === 'aes-256-gcm') {
        decipher = createDecipheriv(this.config.algorithm, key, iv) as DecipherGCM;
        decipher.setAuthTag(authTag);
      } else {
        decipher = createDecipheriv(this.config.algorithm, key, iv) as DecipherCCM;
        (decipher as DecipherCCM).setAuthTag(authTag);
      }

      await ServerLogger.debug('Decipher created', { algorithm: this.config.algorithm });

      const decryptedParts: Uint8Array[] = [];
      decryptedParts.push(new Uint8Array(decipher.update(encryptedData)));
      decryptedParts.push(new Uint8Array(decipher.final()));

      await ServerLogger.debug('Decryption completed', {
        decryptedPartsCount: decryptedParts.length,
      });

      const decryptedData = new Uint8Array(
        decryptedParts.reduce((acc, curr) => acc + curr.length, 0),
      );
      let offset = 0;
      for (const part of decryptedParts) {
        decryptedData.set(part, offset);
        offset += part.length;
      }

      const endTime = process.hrtime(startTime);
      const decryptionTime = (endTime[0] * 1e9 + endTime[1]) / 1e6;

      await ServerLogger.info('Decryption process completed successfully', {
        decryptionTime: `${decryptionTime.toFixed(2)}ms`,
        encryptedLength: encryptedData.length,
        decryptedLength: decryptedData.length,
        ivLength: iv.length,
        saltLength: salt.length,
        authTagLength: authTag.length,
        keyLength: key.length,
      });

      return decryptedData;
    } catch (error) {
      await ServerLogger.error('Error during decryption process', {
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
      });
      throw error;
    }
  },

  async updateConfig(newConfig: EncryptionConfig, newGlobalConfig: GlobalConfig): Promise<void> {
    await ServerLogger.info('Updating ServerEncryptionModule configuration', {
      oldConfig: { ...this.config, encryptionPassword: '[REDACTED]' },
      newConfig: { ...newConfig, encryptionPassword: '[REDACTED]' },
      oldGlobalConfig: { ...this.globalConfig, encryptionPassword: '[REDACTED]' },
      newGlobalConfig: { ...newGlobalConfig, encryptionPassword: '[REDACTED]' },
    });
    this.config = newConfig;
    this.globalConfig = newGlobalConfig;
  },
};

// Add an unhandled rejection handler
process.on('unhandledRejection', async (reason: unknown, promise: Promise<unknown>) => {
  await ServerLogger.error('Unhandled Rejection at:', {
    promise,
    reason: reason instanceof Error ? reason.message : String(reason),
    stack: reason instanceof Error ? reason.stack : undefined,
  });
});
