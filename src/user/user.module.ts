import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { MailerModule } from '../nodemailer/nodemailer.module';
import { User, UserSchema } from './models/user.schema';
import { ApiModule } from '../common/Api/api.module';
import { UserService } from './service/user.service';
import { ProfileController } from './controller/profile.controller';
import { AdminController } from './controller/admin.controller';
import { AuthModule } from 'src/auth/auth.module';
import { AuthController } from './controller/auth.controller';

@Module({
  controllers: [ProfileController, AdminController, AuthController],
  providers: [UserService],
  imports: [
    // UploadModule,
    MailerModule,
    ApiModule,
    AuthModule,
    MongooseModule.forFeatureAsync([
      {
        name: User.name,
        useFactory: async () => {
          const schema = UserSchema;
          return schema;
        },
      },
    ]),
  ],
  exports: [UserService],
})
export class UserModule {}
