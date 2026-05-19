import path from 'path';
import fsp from 'fs/promises';
import pino from 'pino';
import { Server as TusServer } from '@tus/server';
import { FileStore } from '@tus/file-store';
import type { Request, Response, RequestHandler } from 'express';
import type { Upload } from '@tus/utils';
import type { Session } from './types';

export interface TusHandlerOpts {
  scratchDir: string;
  maxUploadBytes: number;
  getSession: (req: Request) => Session | undefined;
  onUploadFinished: (
    sess: Session,
    info: { id: string; name: string; size: number; filePath: string }
  ) => void;
  logger: pino.Logger;
}

export interface TusHandlerResult {
  middleware: RequestHandler;
}

// Sanitize an upload filename: keep only the basename and replace
// unsafe characters with underscores.
function sanitizeFilename(raw: string): string {
  const base = path.basename(raw);
  return base.replace(/[^\w.\-]+/g, '_') || 'artifact.bin';
}

export function createTusHandler(opts: TusHandlerOpts): TusHandlerResult {
  const { scratchDir, maxUploadBytes, getSession, onUploadFinished, logger } = opts;

  const tusDir = path.join(scratchDir, '_tus');

  const server = new TusServer({
    path: '/api/tus',
    relativeLocation: true,
    datastore: new FileStore({ directory: tusDir }),

    onUploadCreate: async (req, res, upload: Upload) => {
      // Typecast to access Express cookie parsing — tus passes http.IncomingMessage
      // but Express has augmented it in our handler chain.
      const expressReq = req as unknown as Request;
      const sess = getSession(expressReq);
      if (!sess) {
        throw { status_code: 401, body: 'No session' };
      }

      const size = upload.size;
      if (size == null) {
        throw { status_code: 400, body: 'Upload-Length header is required' };
      }
      if (size > maxUploadBytes) {
        throw {
          status_code: 413,
          body: `Upload size ${size} exceeds the limit of ${maxUploadBytes} bytes`,
        };
      }

      // Stamp the upload with the session id so we can verify it on finish.
      const metadata = { ...(upload.metadata ?? {}), sid: sess.sid };
      logger.debug({ sid: sess.sid, uploadId: upload.id }, 'tus upload created');
      return { res, metadata };
    },

    onUploadFinish: async (req, res, upload: Upload) => {
      const expressReq = req as unknown as Request;
      const sess = getSession(expressReq);
      if (!sess) {
        throw { status_code: 401, body: 'No session' };
      }

      // Verify the upload belongs to this session.
      const uploadSid = upload.metadata?.['sid'];
      if (uploadSid !== sess.sid) {
        throw { status_code: 403, body: 'Upload does not belong to this session' };
      }

      const rawName =
        upload.metadata?.['filename'] ??
        upload.metadata?.['name'] ??
        'artifact.bin';
      const name = sanitizeFilename(rawName);

      const tusDataPath = path.join(tusDir, upload.id);
      const destPath = path.join(sess.dir, 'upload', name);

      try {
        await fsp.rename(tusDataPath, destPath);
      } catch (e) {
        logger.error({ uploadId: upload.id, err: e }, 'failed to move tus data file');
        throw { status_code: 500, body: 'Failed to move upload to session directory' };
      }

      // Clean up tus sidecar metadata JSON if present.
      try {
        await fsp.unlink(tusDataPath + '.json');
      } catch (_) {}

      const size = upload.size ?? 0;

      onUploadFinished(sess, { id: upload.id, name, size, filePath: destPath });
      logger.info(
        { sid: sess.sid, uploadId: upload.id, name, size },
        'tus upload finished'
      );

      // Return a JSON body with upload info. Tus spec allows response bodies;
      // most clients ignore non-204 status but we return 200 with JSON.
      return {
        res,
        status_code: 200,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ uploadId: upload.id, name, size }),
      };
    },
  });

  const middleware: RequestHandler = (req: Request, res: Response) => {
    void server.handle(req, res);
  };

  return { middleware };
}
