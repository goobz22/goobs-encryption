export type LogLevel = 'error' | 'warn' | 'info' | 'http' | 'verbose' | 'debug';

export interface GlobalConfig {
  loggingEnabled: boolean;
  logLevel: LogLevel;
  logDirectory: string;
}
