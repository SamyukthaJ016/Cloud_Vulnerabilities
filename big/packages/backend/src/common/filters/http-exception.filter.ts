import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';

/**
 * Global exception filter. Converts all unhandled errors into a consistent
 * JSON envelope and logs 5xx with a stack trace.
 *
 * Response shape:
 *   { statusCode, message, error, path, timestamp }
 */
@Catch()
export class HttpExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger('HttpExceptionFilter');

  catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const res = ctx.getResponse();
    const req = ctx.getRequest();

    const status = exception instanceof HttpException ? exception.getStatus() : HttpStatus.INTERNAL_SERVER_ERROR;
    const body = exception instanceof HttpException ? exception.getResponse() : 'Internal server error';

    if (status >= 500) {
      this.logger.error(`${req.method} ${req.originalUrl}`, (exception as Error)?.stack);
    }

    res.status(status).json({
      statusCode: status,
      ...(typeof body === 'string' ? { message: body } : (body as object)),
      path: req.originalUrl,
      timestamp: new Date().toISOString(),
    });
  }
}
