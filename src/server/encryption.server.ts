'use server';

import { promisify } from 'util';
import {
  randomBytes,
  scrypt,
  createCipheriv,
  createDecipheriv,
  CipherGCM,
  DecipherGCM,
} from 'crypto';
import { GlobalConfig } from '../types';
import { ServerLogger } from 'goobs-testing';
import type { EncryptedData } from '../types';

const randomBytesAsync = promisify(randomBytes);
const scryptAsync = promisify(scrypt);

const ENCRYPTION_ALGORITHM = 'aes-256-gcm';

export const ServerEncryptionModule = {
  encryptionPassword: '',
  globalConfig: {} as GlobalConfig,

  async initialize(encryptionPassword: string, globalConfig: GlobalConfig): Promise<void> {
    this.encryptionPassword = encryptionPassword;
    this.globalConfig = globalConfig;
    await ServerLogger.info('ServerEncryptionModule initialized', {
      encryptionPassword: '[REDACTED]',
      globalConfig: { ...globalConfig, encryptionPassword: '[REDACTED]' },
      algorithm: ENCRYPTION_ALGORITHM,
    });
  },

  async deriveKey(password: string, salt: Buffer): Promise<Buffer> {
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

  async encrypt<T>(value: T): Promise<EncryptedData<T>> {
    await ServerLogger.info('Starting encryption process', {
      valueType: typeof value,
      algorithm: ENCRYPTION_ALGORITHM,
    });

    const startTime = process.hrtime();

    try {
      const iv = await randomBytesAsync(16);
      const salt = await randomBytesAsync(16);
      const key = await this.deriveKey(this.encryptionPassword, salt);

      const cipher = createCipheriv(ENCRYPTION_ALGORITHM, key, iv) as CipherGCM;

      await ServerLogger.debug('Cipher created', { algorithm: ENCRYPTION_ALGORITHM });

      const valueString = JSON.stringify(value);
      const encryptedBuffer = Buffer.concat([cipher.update(valueString, 'utf8'), cipher.final()]);

      const authTag = cipher.getAuthTag();

      const endTime = process.hrtime(startTime);
      const encryptionTime = (endTime[0] * 1e9 + endTime[1]) / 1e6;

      await ServerLogger.info('Encryption process completed successfully', {
        encryptionTime: `${encryptionTime.toFixed(2)}ms`,
        inputLength: valueString.length,
        encryptedLength: encryptedBuffer.length,
        ivLength: iv.length,
        saltLength: salt.length,
        authTagLength: authTag.length,
        keyLength: key.length,
      });

      return {
        encryptedValue: encryptedBuffer as unknown as T,
        iv,
        salt,
        authTag,
      };
    } catch (error) {
      await ServerLogger.error('Error during encryption process', {
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
      });
      throw error;
    }
  },

  async decrypt<T>(encryptedData: EncryptedData<T>): Promise<T> {
    await ServerLogger.info('Starting decryption process', {
      encryptedDataLength: (encryptedData.encryptedValue as unknown as Buffer).length,
      algorithm: ENCRYPTION_ALGORITHM,
      ivLength: encryptedData.iv.length,
      saltLength: encryptedData.salt.length,
      authTagLength: encryptedData.authTag.length,
    });

    const startTime = process.hrtime();

    try {
      const { encryptedValue, iv, salt, authTag } = encryptedData;
      const key = await this.deriveKey(this.encryptionPassword, salt);

      await ServerLogger.debug('Decryption key derived', { keyLength: key.length });

      const decipher = createDecipheriv(ENCRYPTION_ALGORITHM, key, iv) as DecipherGCM;
      decipher.setAuthTag(authTag);

      await ServerLogger.debug('Decipher created', { algorithm: ENCRYPTION_ALGORITHM });

      const decryptedBuffer = Buffer.concat([
        decipher.update(encryptedValue as unknown as Buffer),
        decipher.final(),
      ]);

      const decryptedValue = JSON.parse(decryptedBuffer.toString('utf8')) as T;

      const endTime = process.hrtime(startTime);
      const decryptionTime = (endTime[0] * 1e9 + endTime[1]) / 1e6;

      await ServerLogger.info('Decryption process completed successfully', {
        decryptionTime: `${decryptionTime.toFixed(2)}ms`,
        encryptedLength: (encryptedValue as unknown as Buffer).length,
        decryptedLength: decryptedBuffer.length,
        ivLength: iv.length,
        saltLength: salt.length,
        authTagLength: authTag.length,
        keyLength: key.length,
      });

      return decryptedValue;
    } catch (error) {
      await ServerLogger.error('Error during decryption process', {
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
      });
      throw error;
    }
  },

  async updateConfig(newEncryptionPassword: string, newGlobalConfig: GlobalConfig): Promise<void> {
    await ServerLogger.info('Updating ServerEncryptionModule configuration', {
      oldEncryptionPassword: '[REDACTED]',
      newEncryptionPassword: '[REDACTED]',
      oldGlobalConfig: { ...this.globalConfig, encryptionPassword: '[REDACTED]' },
      newGlobalConfig: { ...newGlobalConfig, encryptionPassword: '[REDACTED]' },
    });
    this.encryptionPassword = newEncryptionPassword;
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
