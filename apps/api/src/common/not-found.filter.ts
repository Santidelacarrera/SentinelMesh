import { ArgumentsHost, Catch, ExceptionFilter, NotFoundException } from '@nestjs/common';
import { RowNotFound } from '../store/store';

/** A row that is missing OR belongs to another organisation is the same thing to the caller: 404, never 500 and never a hint that it exists elsewhere. */
@Catch(RowNotFound)
export class RowNotFoundFilter implements ExceptionFilter {
  catch(_e: RowNotFound, host: ArgumentsHost) {
    const res = host.switchToHttp().getResponse(), ex = new NotFoundException('not found');
    res.status(404).json(ex.getResponse());
  }
}
