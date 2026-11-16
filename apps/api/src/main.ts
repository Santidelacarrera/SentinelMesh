import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { json } from 'express';
import { INestApplication } from '@nestjs/common';
import { AppModule } from './app.module';

export async function bootstrap(port = Number(process.env.PORT ?? 3000)): Promise<INestApplication> {
  const app = await NestFactory.create(AppModule, { bodyParser: true, logger: process.env.NODE_ENV === 'test' ? false : undefined });
  app.use(json({ limit: '10mb' }));
  // CORS is closed unless the operator lists origins (the console is served same-origin behind the proxy).
  const origins = (process.env.CORS_ORIGINS ?? '').split(',').map((o) => o.trim()).filter(Boolean);
  if (origins.length) app.enableCors({ origin: origins, methods: ['GET', 'POST', 'OPTIONS'], allowedHeaders: ['authorization', 'content-type', 'x-api-key'], maxAge: 600 });
  app.enableShutdownHooks();
  await app.listen(port);
  return app;
}

if (require.main === module) void bootstrap();
