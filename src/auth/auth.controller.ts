import { IAuthUser } from '../common/types';
import { AuthService } from './auth.service';
import { Controller, Get, Res, UseGuards } from '@nestjs/common';
import { AuthUser } from '../common/decorator/user.decorator';
import { RefreshGuard } from './guards/refresh.guard';
import { Response } from 'express';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}
  @Get('refresh')
  @UseGuards(RefreshGuard)
  refresh(@Res() res: Response, @AuthUser() user: IAuthUser) {
    return this.authService.refreshToken(user, res);
  }
}
