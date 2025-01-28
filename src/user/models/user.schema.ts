import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument, Query } from 'mongoose';
import { All_Role } from 'src/common/enum';

@Schema({
  timestamps: true,
})
export class User {
  @Prop({})
  name: string;

  @Prop({ type: String })
  passwordResetCode: string;

  @Prop({ type: Date })
  passwordResetCodeExpiresIn: Date;

  @Prop({ type: Date })
  passwordChangedAt: Date;

  @Prop({ type: String })
  emailVerificationCode: string;

  @Prop({ type: Date })
  emailVerificationCodeExpiresIn: Date;

  @Prop({ type: Boolean, default: false })
  isVerifiedEmail: boolean;

  @Prop({
    required: true,
  })
  email: string;

  @Prop()
  password: string;

  @Prop({ default: All_Role.User, enum: All_Role })
  role: string;

  @Prop({ type: String })
  icon: string;

  @Prop({
    type: String,
    trim: true,
  })
  fcm: string;

  @Prop({
    type: Boolean,
    default: false,
  })
  isDeleted: boolean;

  @Prop({
    type: String,
    trim: true,
  })
  phone: string;
}
export type UserDocument = HydratedDocument<User>;
export const UserSchema = SchemaFactory.createForClass(User);
UserSchema.pre<Query<any, any>>(/^find/, function () {
  if (!this.getOptions().skipFilter) {
    this.find({
      isDeleted: false,
    });
  }
});
