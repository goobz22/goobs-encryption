export interface EncryptedValue {
  type: 'encrypted';
  encryptedData: Uint8Array;
  iv: Uint8Array;
  salt: Uint8Array;
  authTag: Uint8Array;
  encryptionKey: Uint8Array;
}

export interface EncryptionConfig {
  algorithm: string;
  encryptionPassword: string;
  keyCheckIntervalMs: number;
  keyRotationIntervalMs: number;
}

export type LogLevel = 'error' | 'warn' | 'info' | 'http' | 'verbose' | 'debug';

export interface GlobalConfig {
  loggingEnabled: boolean;
  logLevel: LogLevel;
  logDirectory: string;
}
