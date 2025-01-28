import { Module } from '@nestjs/common';
import { MailerService } from './nodemailer.service';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';

@Module({
  providers: [
    MailerService,
    {
      provide: 'TRANSPORTER',
      useFactory: function (config: ConfigService) {
        return nodemailer.createTransport({
          host: config.get('host'),
          port: config.get('port'),
          secure: config.get('secure'),
          auth: {
            user: config.get('user'),
            pass: config.get('pass'),
          },
        });
      },
      inject: [ConfigService],
    },
  ],
  exports: [MailerService],
})
export class MailerModule {}
