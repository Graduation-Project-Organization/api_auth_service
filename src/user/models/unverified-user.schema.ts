import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument } from 'mongoose';

@Schema({})
export class UnverifiedUser {
  @Prop({})
  email: string;

  @Prop({})
  password: string;

  @Prop({})
  name: string;

  @Prop({})
  icon: string;

  @Prop({})
  role: string;

  @Prop({})
  fcm: string;

  @Prop({})
  phone: string;

  @Prop({})
  verificationToken: string;

  @Prop({})
  expiresIn: Date;

  @Prop({ default: Date.now, expires: 86400 }) // Automatically deletes after 24h
  createdAt: Date;
}
export type UnverifiedUserDocument = HydratedDocument<UnverifiedUser>;
export const UnverifiedUserSchema =
  SchemaFactory.createForClass(UnverifiedUser);
