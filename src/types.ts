import type { Response } from 'express';
import type { ChildProcess } from 'child_process';
import type { FSWatcher } from 'fs';

export type JobState = 'queued' | 'running' | 'done' | 'failed' | 'cancelled';
export type SessionState = 'idle' | JobState;
export type PasswordTransport = 'none' | 'env' | 'file';
export type SandboxKind = 'none' | 'bwrap' | 'firejail';
export type SandboxMode = 'auto' | SandboxKind;

export interface ServerConfig {
  port: number;
  host: string;
  maxUploadBytes: number;
  extractSbomBin: string;
  extraArgs: string[];
  scratchDir: string;
  maxLogLines: number;
  sessionIdleMs: number;
  uploadRatePerMin: number;
  trustProxy: boolean;
  authUser: string | null;
  authPass: string | null;
  shutdownGraceMs: number;
  logLevel: string;
  logPretty: boolean;
  sandboxMode: SandboxMode;
}

export interface LogEntry {
  t: number;
  stream: 'stdout' | 'stderr';
  line: string;
}

export interface OutputFile {
  name: string;
  size: number;
  mtime: number;
}

export interface PhaseHit {
  phase: string;
  progress: number | null;
}

export interface Job {
  id: string;
  state: JobState;
  command: string;
  args: string[];
  argsDisplay: string[];
  child: ChildProcess | null;
  pid: number | null;
  exitCode: number | null;
  signal: NodeJS.Signals | null;
  error: string | null;
  startedAt: number | null;
  finishedAt: number | null;
  createdAt: number;
  inputName: string;
  inputSize: number;
  uploadPath: string;
  passwordCount: number;
  passwordTransport: PasswordTransport;
  passwordFile: string | null;
  outDir: string;
  outputs: OutputFile[];
  log: LogEntry[];
  phase: string | null;
  progress: number | null;
  sandbox: SandboxKind;
  inputSha256: string | null;
}

export interface Session {
  sid: string;
  dir: string;
  jobs: Job[];
  currentJobIdx: number | null;
  createdAt: number;
  lastActivity: number;
  sseClients: Set<Response>;
  outputWatcher: FSWatcher | null;
  pendingUploadId: string | null;
  pendingUploadPath: string | null;
  pendingUploadName: string | null;
  pendingUploadSize: number | null;
}

export interface JobSnapshot {
  id: string;
  state: JobState;
  command: string;
  args: string[];
  pid: number | null;
  inputName: string;
  inputSize: number;
  passwordCount: number;
  passwordTransport: PasswordTransport;
  createdAt: number;
  startedAt: number | null;
  finishedAt: number | null;
  exitCode: number | null;
  signal: NodeJS.Signals | null;
  error: string | null;
  outputs: OutputFile[];
  phase: string | null;
  progress: number | null;
  sandbox: SandboxKind;
}

export interface PendingUpload {
  id: string;
  name: string;
  size: number;
}

export interface SessionSnapshot {
  sessionId: string;
  sessionStartedAt: number;
  state: SessionState;
  currentJobId: string | null;
  pendingUpload: PendingUpload | null;
  jobs: JobSnapshot[];
}
