import {
  Body,
  Controller,
  HttpException,
  Param,
  Post,
  Res,
} from '@nestjs/common';
import { Response } from 'express';
import { UserService } from '../service/user.service';
import { LoginDto } from '../dto/login.user.dto';
import { CreateUserDto } from '../dto/create.user.dto';
import { ForgetPasswordDto } from '../dto/forget-password.dto';
import { ValidateOtpCode } from '../dto/otp-code.dto';
// import { FileInterceptor } from '@nestjs/platform-express';

@Controller('auth')
export class AuthController {
  constructor(private userService: UserService) {}
  @Post('login')
  login(@Body() body: LoginDto, @Res() res: Response) {
    return this.userService.login(body, res);
  }

  @Post('logout')
  logout(@Res() res: Response) {
    return this.userService.logout(res);
  }

  @Post('signup')
  // @UseInterceptors(FileInterceptor('icon'))
  createUser(
    @Body() body: CreateUserDto,
    // @Res() res: Response,
    // @UploadedFile() file: Express.Multer.File,
  ) {
    return this.userService.createUser(body);
  }

  @Post('forget-password')
  sendChangingPasswordCode(@Body() body: ForgetPasswordDto) {
    return this.userService.sendChangingPasswordCode(body.email);
  }

  @Post('validate-forget-password-code')
  validatePasswordCode(@Body() body: ValidateOtpCode) {
    return this.userService.validateCode(body.code, body.password);
  }

  @Post('validate-verification-code/:code')
  verificationEmailCode(@Param('code') code: string, @Body('email') email: string, @Res() res:Response) {
    if(!code || !email){
      throw new HttpException('email or code not found ', 400);
    }
    return this.userService.verifyEmail(code, email, res);
  }

  @Post('resend-verification-code')
  resendVerificationEmailCode(@Body('email') email: string) {
    return this.userService.resendVerificationCode(email);
  }
}
