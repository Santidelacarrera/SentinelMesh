import { BadRequestException } from '@nestjs/common';
import { ZodType } from 'zod';
/** Strict boundary validation; unknown keys are rejected by the schemas' `.strict()`. */
export function parse<T>(schema: ZodType<T>, body: unknown): T {
  const r = schema.safeParse(body);
  if (!r.success) throw new BadRequestException({ message: 'validation failed', issues: r.error.issues.map((i) => ({ path: i.path.join('.'), message: i.message })) });
  return r.data;
}
