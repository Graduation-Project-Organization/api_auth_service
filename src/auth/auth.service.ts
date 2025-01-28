import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { Response } from 'express';
import { IAuthUser } from '../common/types';

@Injectable()
export class AuthService {
  constructor(
    private jwt: JwtService,
    private config: ConfigService,
  ) {}
  async createRefreshToken(userId: string, role: string) {
    const refreshToken = await this.jwt.sign(
      { userId, role },
      { secret: this.config.get('refresh_secret'), expiresIn: '7d' },
    );
    return refreshToken;
  }
  async createAccessToken(userId: string, role: string) {
    const accessToken = await this.jwt.signAsync(
      { userId, role },
      { secret: this.config.get('access_secret'), expiresIn: '5h' },
    );
    return accessToken;
  }
  async refreshToken(user: IAuthUser, res: Response) {
    const accessToken = await this.createAccessToken(
      user._id.toString(),
      user.role,
    );
    const refreshToken = await this.createRefreshToken(user._id, user.role);
    res.status(200).json({ accessToken, user, refreshToken });
  }
}
