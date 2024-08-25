export type LogLevel = 'error' | 'warn' | 'info' | 'http' | 'verbose' | 'debug';

export interface GlobalConfig {
  loggingEnabled: boolean;
  logLevel: LogLevel;
  logDirectory: string;
}

export interface EncryptedData<T> {
  encryptedValue: T;
  iv: Buffer;
  salt: Buffer;
  authTag: Buffer;
}
