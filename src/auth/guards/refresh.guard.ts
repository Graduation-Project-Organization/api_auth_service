import { Injectable, UnauthorizedException } from '@nestjs/common';
import { Request } from 'express';
import { AuthenticationGuard } from '../../common/guard/authentication.guard';

@Injectable()
export class RefreshGuard extends AuthenticationGuard {
  extractToken(request: Request) {
    let token: string = request.headers.authorization;
    if (!token || !token.startsWith('Bearer')) {
      throw new UnauthorizedException('Authorization header is missing');
    }
    token = token.split(' ')[1];
    return this.decode(token, this.config.get('refresh_secret'));
  }
}
