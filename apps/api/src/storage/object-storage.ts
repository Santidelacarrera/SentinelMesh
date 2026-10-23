import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, resolve, sep } from 'node:path';

/** S3/MinIO-shaped contract. In-memory and filesystem backends ship; an S3 adapter implements the same 3 methods. */
export interface ObjectStorage {
  put(key: string, body: Buffer | string): Promise<void>;
  get(key: string): Promise<Buffer | undefined>;
}
export const OBJECT_STORAGE = Symbol('OBJECT_STORAGE');

export class MemoryObjectStorage implements ObjectStorage {
  private m = new Map<string, Buffer>();
  async put(k: string, b: Buffer | string) { this.m.set(k, Buffer.from(b)); }
  async get(k: string) { return this.m.get(k); }
}

export class FsObjectStorage implements ObjectStorage {
  constructor(private root: string) {}
  private path(key: string) {
    const p = resolve(join(this.root, key));
    if (!p.startsWith(resolve(this.root) + sep)) throw new Error('invalid key');
    return p;
  }
  // Paths below come from this.path(), which resolves the key under `root` and rejects any escape (../, absolute paths).
  /* eslint-disable security/detect-non-literal-fs-filename */
  async put(k: string, b: Buffer | string) { const p = this.path(k); await mkdir(dirname(p), { recursive: true }); await writeFile(p, b); }
  async get(k: string) { try { return await readFile(this.path(k)); } catch { return undefined; } }
  /* eslint-enable security/detect-non-literal-fs-filename */
}
