import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { ApiModule } from '../common/Api/api.module';
import { AuthRefreshController } from './auth.controller';
import { MongooseModule } from '@nestjs/mongoose';
import { User, UserSchema } from 'src/user/models/user.schema';

@Module({
  providers: [AuthService],
  imports: [
    ApiModule,
    MongooseModule.forFeature([{ name: User.name, schema: UserSchema }]),
  ],
  exports: [AuthService],
  controllers: [AuthRefreshController],
})
export class AuthModule {}
