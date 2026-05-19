import pino from 'pino';
import pinoHttp from 'pino-http';
import type { IncomingMessage, ServerResponse } from 'http';
import type { ServerConfig } from './types';

// Fields to redact from structured logs to avoid leaking credentials.
const REDACT_PATHS = [
  'req.headers.authorization',
  'req.headers.cookie',
  'res.headers["set-cookie"]',
  'req.body.passwords',
  '*.password',
  '*.passwords',
];

export function createLogger(config: ServerConfig): pino.Logger {
  const opts: pino.LoggerOptions = {
    level: config.logLevel,
    redact: {
      paths: REDACT_PATHS,
      censor: '[REDACTED]',
    },
  };

  if (config.logPretty) {
    // pino-pretty is a dev dep — safe to require at runtime in non-prod.
    return pino({
      ...opts,
      transport: {
        target: 'pino-pretty',
        options: {
          colorize: true,
          translateTime: 'SYS:standard',
          ignore: 'pid,hostname',
        },
      },
    });
  }

  return pino(opts);
}

export function createHttpLogger(
  config: ServerConfig,
  baseLogger: pino.Logger
): ReturnType<typeof pinoHttp<IncomingMessage, ServerResponse>> {
  return pinoHttp<IncomingMessage, ServerResponse>({
    logger: baseLogger,
    // Keep request log lines small: only method, url, status, responseTime.
    customSuccessMessage(req: IncomingMessage, res: ServerResponse, responseTime: number) {
      return `${req.method} ${req.url} ${res.statusCode} ${responseTime}ms`;
    },
    customErrorMessage(req: IncomingMessage, res: ServerResponse) {
      return `${req.method} ${req.url} ${res.statusCode} error`;
    },
    // Don't log heartbeat SSE or health check noise at info; use trace.
    customLogLevel(req: IncomingMessage, res: ServerResponse, err?: Error) {
      if (req.url === '/api/health') return 'trace';
      if (err) return 'error';
      if (res.statusCode >= 500) return 'error';
      if (res.statusCode >= 400) return 'warn';
      return 'info';
    },
    // Only log method, url, and remote address — not full headers.
    serializers: {
      req(req: IncomingMessage & { remoteAddress?: string }) {
        return {
          method: req.method,
          url: req.url,
          remoteAddress: req.remoteAddress,
        };
      },
      res(res: ServerResponse) {
        return {
          statusCode: res.statusCode,
        };
      },
    },
  });
}
