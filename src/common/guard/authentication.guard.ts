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
      throw new UnauthorizedException('User has been deleted');
    }

    if (user.passwordChangedAt) {
      const stamp = user.passwordChangedAt.getTime() / 1000;
      if (stamp > payload.iat) {
        throw new UnauthorizedException('Password has been changed');
      }
    }

    // Attach user info to the request
    request.user = {
      role: user.role,
      _id: payload.userId,
      fcm: user.fcm,
      email: user.email,
      name: user.name,
    };

    return true;
  }

  async extractToken(request: Request) {
    let token: string | undefined;

    if (request.cookies?.jwt) {
      token = request.cookies.jwt;
    }

    if (!token && request.headers.authorization?.startsWith('Bearer ')) {
      token = request.headers.authorization.split(' ')[1];
    }

    if (!token) {
      throw new UnauthorizedException('JWT token is missing from both cookie and header');
    }

    return this.decode(token, this.config.get<string>('access_secret'));
  }

  async decode(token: string, secret: string) {
    try {
      return await this.jwt.verifyAsync(token, { secret });
    } catch (e) {
      throw new UnauthorizedException('Invalid JWT token');
    }
  }
}
