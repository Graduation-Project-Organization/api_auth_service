import { ApiProperty } from '@nestjs/swagger';
import { IsString } from 'class-validator';

export class ValidateOtpCode {
  @ApiProperty()
  @IsString()
  code: string;
  @ApiProperty()
  @IsString()
  password: string;
}
