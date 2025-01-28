import { JwtService } from '@nestjs/jwt';
import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';
import { User, UserDocument } from 'src/user/models/user.schema';

@Injectable()
export class AuthenticationGuard implements CanActivate {
  constructor(
    private readonly jwt: JwtService,
    @InjectModel(User.name) protected readonly userModel: Model<UserDocument>,
    protected config: ConfigService,
  ) {}
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();
    const payload = await this.extractToken(request);
    const user = await this.userModel.findById(payload.userId);
    if (!user) {
      throw new UnauthorizedException('user has been deleted');
    }
    if (user.passwordChangedAt) {
      const stamp = user.passwordChangedAt.getTime() / 1000;
      if (stamp > payload.iat) {
        throw new UnauthorizedException('Password has been changed'); // check if password has been changed
      }
    }
    request.user = {
      role: user.role,
      _id: payload.userId,
      fcm: user.fcm,
      email: user.email,
      name: user.name,
    };
    return true;
  }
  extractToken(request: Request) {
    let token: string = request.headers.authorization;
    if (!token || !token.startsWith('Bearer')) {
      throw new UnauthorizedException('Authorization header is missing');
    }
    token = token.split(' ')[1];
    return this.decode(token, this.config.get('access_secret'));
  }
  async decode(token: string, secret: string) {
    let payload: {
      userId: string;
      role: string;
      walletAddress?: string;
      iat: number;
    };
    try {
      payload = await this.jwt.verifyAsync(token, {
        secret,
      });
    } catch (e) {
      throw new UnauthorizedException('invalid token');
    }
    return payload;
  }
}
