import {
  BadRequestException,
  HttpException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as bcrypt from 'bcryptjs';
import * as crypto from 'crypto';
import { Response } from 'express';
// import { UploadService } from '../upload/upload.service';
import { MailerService } from 'src/nodemailer/nodemailer.service';
import { User, UserDocument } from '../models/user.schema';
import { ApiService } from 'src/common/Api/api.service';
import { AuthService } from 'src/auth/auth.service';
import { QueryUserDto } from '../dto/query.user.dto';
import { CreateUserDto } from '../dto/create.user.dto';
import { ChangePasswordDto } from '../dto/change-password.user.dto';
import { IAuthUser } from 'src/common/types';
import { LoginDto } from '../dto/login.user.dto';
import { UpdateUserDto } from '../dto/update.user.dto';

@Injectable()
export class UserService {
  constructor(
    @InjectModel(User.name) private readonly userModel: Model<UserDocument>,
    private readonly mailerService: MailerService,
    private readonly apiService: ApiService<UserDocument, QueryUserDto>,
    private readonly authService: AuthService,
  ) {}
  private async emailVerification(user: UserDocument) {
    const code = this.mailerService.resetCode();
    user.emailVerificationCode = this.createHash(code);
    user.emailVerificationCodeExpiresIn = new Date(Date.now() + 1 * 60 * 1000);
    user.isVerifiedEmail = false;
    try {
      await this.mailerService.sendVerifyEmail({
        mail: user.email,
        name: user.name,
        code: code,
      });
    } catch (err) {
      user.emailVerificationCode = undefined;
      user.emailVerificationCodeExpiresIn = undefined;
      await user.save();
      throw new HttpException('nodemailer error', 400);
    }
    await user.save();
  }
  async resendVerificationCode(email: string) {
    const user = await this.userModel.findOne({ email });
    if (!user) {
      throw new HttpException('user not found', 404);
    }
    if (user.isVerifiedEmail) {
      throw new HttpException('your email has been verified already', 400);
    }
    await this.emailVerification(user);
    return { status: 'code sent' };
  }
  async verifyEmail(code: string) {
    const hash = this.createHash(code);
    const user = await this.userModel.findOne({
      emailVerificationCode: hash,
      emailVerificationCodeExpiresIn: { $gt: Date.now() },
    });
    if (!user) {
      throw new HttpException('email Verified Code expired', 400);
    }
    user.emailVerificationCode = undefined;
    user.emailVerificationCodeExpiresIn = undefined;
    user.isVerifiedEmail = true;
    await user.save();
    return { message: 'email verified' };
  }
  async createUser(body: CreateUserDto) {
    await this.validateUniqueEmail(body.email);
    body.password = await bcrypt.hash(body.password, 10);
    const user = await this.userModel.create(body);
    user.password = undefined;
    await this.emailVerification(user);
    const accessToken = await this.authService.createAccessToken(
      user._id.toString(),
      user.role,
    );
    const refreshToken = await this.authService.createRefreshToken(
      user._id.toString(),
      user.role,
    );
    return { user, accessToken, refreshToken };
  }
  async getFcmToken(userId: string) {
    const user = await this.userModel.findById(userId);
    if (!user) {
      return null;
    }
    return user.fcm;
  }
  async validateUniqueEmail(email: string) {
    const userExist = await this.userModel
      .findOne({ email })
      .setOptions({ skipFilter: true });
    if (userExist) {
      throw new HttpException('email already exists', 400);
    }
  }
  async changeLoggedUserPassword(body: ChangePasswordDto, IUser: IAuthUser) {
    const user = await this.userModel.findById(IUser._id);
    const valid = await bcrypt.compare(body.currentPassword, user.password);
    if (!valid) {
      throw new HttpException('current password is not valid', 400);
    }
    user.password = await bcrypt.hash(body.password, 10);
    user.passwordChangedAt = new Date();
    await user.save();
    return { user };
  }
  async login(body: LoginDto, res: Response) {
    const user = await this.userModel.findOne({ email: body.email });
    if (!user) {
      throw new NotFoundException('user not found');
    }
    const valid = await bcrypt.compare(body.password, user.password);
    if (!valid) {
      throw new BadRequestException('email or password is not correct');
    }
    const accessToken = await this.authService.createAccessToken(
      user._id.toString(),
      user.role,
    );
    const refreshToken = await this.authService.createRefreshToken(
      user._id.toString(),
      user.role,
    );
    user.password = undefined;
    res.status(200).json({ accessToken, user, refreshToken });
  }
  createHash(code: string) {
    return crypto.createHash('sha256').update(code).digest('hex');
  }
  async sendChangingPasswordCode(email: string) {
    const user = await this.userModel.findOne({ email: email });
    if (!user) {
      throw new NotFoundException('user not found');
    }
    const code = this.mailerService.resetCode();
    const hash = this.createHash(code);
    user.passwordResetCode = hash;
    user.passwordResetCodeExpiresIn = new Date(Date.now() + 5 * 60 * 100);
    try {
      await this.mailerService.sendChangingPasswordCode({
        code,
        mail: user.email,
        name: user.name || 'client',
      });
    } catch (e) {
      user.passwordResetCodeExpiresIn = undefined;
      user.passwordResetCode = undefined;
      await user.save();
      throw new BadRequestException('Failed to send code');
    }
    await user.save();
    return { message: 'code sent successfully' };
  }
  async validateCode(code: string, password: string) {
    const hash = this.createHash(code);
    const user = await this.userModel.findOne({ passwordResetCode: hash });
    if (!user) {
      throw new BadRequestException('code is invalid');
    }
    user.passwordResetCode = undefined;
    user.passwordResetCodeExpiresIn = undefined;
    user.password = await bcrypt.hash(password, 10);
    user.passwordChangedAt = new Date();
    await user.save();
    return { user };
  }
  async getOneUser(userId: string) {
    const user = await this.userModel.findById(userId);
    if (!user) {
      throw new NotFoundException('user not found');
    }
    return { user };
  }
  async getAllUsers(obj: QueryUserDto) {
    const { query, paginationObj } = await this.apiService.getAllDocs(
      this.userModel.find(),
      obj,
    );
    const users = await query;
    return { users, pagination: paginationObj };
  }
  async deleteUser(userId: string) {
    const user = await this.userModel.findByIdAndUpdate(
      userId,
      {
        isDeleted: true,
      },
      { new: true },
    );
    console.log(user);
    if (!user) {
      throw new NotFoundException('user not found');
    }
    return { status: 'user deleted' };
  }
  async updateUser(userId: string, body: UpdateUserDto) {
    const user = await this.userModel.findByIdAndUpdate(userId, body, {
      new: true,
    });
    if (!user) {
      throw new NotFoundException('user not found');
    }
    return { user };
  }
}
