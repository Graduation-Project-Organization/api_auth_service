import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { MongooseModule } from '@nestjs/mongoose';
import { UserModule } from './user/user.module';
import { catchExceptionsFilter } from './common/global-filter';
import { APP_FILTER } from '@nestjs/core';
import { RabbitMqConfigModule } from './config/rabbitmq-config.module';
import { AuthModule } from './auth/auth.module';
@Module({
  imports: [
    RabbitMqConfigModule,
    JwtModule.register({
      global: true,
      // signOptions: { expiresIn: '50d' },
    }),
    ConfigModule.forRoot({ isGlobal: true }),
    MongooseModule.forRootAsync({
      inject: [ConfigService],
      useFactory: function (config: ConfigService) {
        return {
          uri: config.get<string>('Mongo_Uri'),
        };
      },
    }),
    UserModule,
    AuthModule,
  ],
  controllers: [],
  providers: [{ provide: APP_FILTER, useClass: catchExceptionsFilter }],
})
export class AppModule {
  // MiddlewareConsumer is used to configure the middleware vvv
  // configure(consumer: MiddlewareConsumer) {
  //   consumer
  //     .apply(CheckHeaderMiddleware /* , otherMiddleWare */)
  //     .forRoutes(
  //       { path: '*', method: RequestMethod.ALL } /* OR AppController */,
  //     );
  //   /*  // to implement other middleware:
  //        consumer
  //             .apply(NewMiddleware)
  //             .forRoutes({ path: 'demo', method: RequestMethod.GET });*/
  // }
}
