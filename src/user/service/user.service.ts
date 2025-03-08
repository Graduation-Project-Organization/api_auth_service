import { BadRequestException, HttpException, Injectable, NotFoundException } from "@nestjs/common";
import { InjectModel } from "@nestjs/mongoose";
import { User, UserDocument } from "../models/user.schema";
import { Model } from "mongoose";
import { MailerService } from "src/nodemailer/nodemailer.service";
import { UnverifiedUser, UnverifiedUserDocument } from "../models/unverified-user.schema";
import { AuthService } from "src/auth/auth.service";
import { CreateUserDto } from "../dto/create.user.dto";
import * as bcrypt from 'bcryptjs';
import { ChangePasswordDto } from "../dto/change-password.user.dto";
import { IAuthUser } from "src/common/types";
import { LoginDto } from "../dto/login.user.dto";
import { Response } from "express";
import * as crypto from 'crypto';
import { UpdateUserDto } from "../dto/update.user.dto";

@Injectable()
export class UserService {
  constructor(
    @InjectModel(User.name) private readonly userModel: Model<UserDocument>,
    private readonly mailerService: MailerService,
    // private readonly uploadService: UploadService,
    private readonly authService: AuthService,
    @InjectModel(UnverifiedUser.name)
    private readonly UnverifiedUserModel: Model<UnverifiedUserDocument>,
  ) {}
  async createUser(body: CreateUserDto) {
    await this.validateUniqueEmail(body.email);
    await this.emailVerification(body);
    return { message: 'email verification code sent' };
  }
  private async emailVerification(body: CreateUserDto) {
    const code = this.mailerService.resetCode();
    await this.UnverifiedUserModel.deleteMany({ email: body.email });
    body.password = await bcrypt.hash(body.password, 10);
    const verification = await this.UnverifiedUserModel.create(body);
    verification.verificationToken = this.createHash(code);
    verification.expiresIn = new Date(Date.now() + 3 * 60 * 1000);
    try {
      await this.mailerService.sendVerifyEmail({
        mail: verification.email,
        name: verification.name,
        code: code,
      });
    } catch (err) {
      await verification.deleteOne();
      throw new HttpException('nodemailer error', 400);
    }
    await verification.save();
  }
  async resendVerificationCode(email: string) {
    const verification = await this.UnverifiedUserModel.findOne({ email });
    if (!verification) {
      throw new NotFoundException('User not found');
    }
    const code = this.mailerService.resetCode();
    verification.verificationToken = this.createHash(code);
    verification.expiresIn = new Date(Date.now() + 2 * 60 * 1000);
    try {
      await this.mailerService.sendVerifyEmail({
        mail: verification.email,
        name: verification.name,
        code: code,
      });
    } catch (err) {
      throw new HttpException('nodemailer error', 400);
    }
    await verification.save();
    return { message: 'email verification code sent' };
  }
  async verifyEmail(code: string, email: string) {
    const hash = this.createHash(code);
    const verification = await this.UnverifiedUserModel.findOne({
      verificationToken: hash,
      expiresIn: { $gt: Date.now() },
      email,
    });
    if (!verification) {
      throw new HttpException('email Verified Code expired', 400);
    }
    const user = await this.userModel.create({
      password: verification.password,
      email: verification.email,
      name: verification.name,
      icon: verification.icon,
      role: verification.role,
      fcm: verification.fcm,
      phonr: verification.phone,
    });
    await verification.deleteOne();
    const accessToken = await this.authService.createAccessToken(
      user._id.toString(),
      user.role,
      user.email,
      user.name,
    );
    const refreshToken = await this.authService.createRefreshToken(
      user._id.toString(),
      user.role,
    );
    user.password = undefined;
    user.passwordChangedAt = undefined;
    user.passwordResetCode = undefined;
    user.passwordResetCodeExpiresIn = undefined;
    user.isDeleted = undefined;
    user.fcm = undefined;
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
  findOneById(id: string) {
    return this.userModel.findById(id);
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
    user.password = undefined;
    user.passwordChangedAt = undefined;
    user.passwordResetCode = undefined;
    user.passwordResetCodeExpiresIn = undefined;
    user.isDeleted = undefined;
    user.fcm = undefined;
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
      user.email,
      user.name,
    );
    const refreshToken = await this.authService.createRefreshToken(
      user._id.toString(),
      user.role,
    );
    user.password = undefined;
    user.passwordChangedAt = undefined;
    user.passwordResetCode = undefined;
    user.passwordResetCodeExpiresIn = undefined;
    user.isDeleted = undefined;
    user.fcm = undefined;
    res.
      status(200)
      .json({ accessToken, user, refreshToken });
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
        name: user.name || 'user',
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

    // structure rturned object
    user.password = undefined;
    user.passwordChangedAt = undefined;
    user.passwordResetCode = undefined;
    user.passwordResetCodeExpiresIn = undefined;
    user.isDeleted = undefined;
    user.fcm = undefined;
    return { user };
  }
  async getOneUser(userId: string) {
    const user = await this.userModel.findById(userId);
    if (!user) {
      throw new NotFoundException('user not found');
    }
    user.password = undefined;
    user.passwordChangedAt = undefined;
    user.passwordResetCode = undefined;
    user.passwordResetCodeExpiresIn = undefined;
    user.isDeleted = undefined;
    user.fcm = undefined;
    return { user };
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
  async updateUser(
    userId: string,
    body: UpdateUserDto,
    // file: Express.Multer.File,
  ) {
    const user = await this.userModel.findByIdAndUpdate(userId, body, {
      new: true,
    });
    if (!user) {
      throw new NotFoundException('user not found');
    }
    user.password = undefined;
    user.passwordChangedAt = undefined;
    user.passwordResetCode = undefined;
    user.passwordResetCodeExpiresIn = undefined;
    user.isDeleted = undefined;
    user.fcm = undefined;
    return { user };
  }
}
