import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsOptional } from 'class-validator';

export class FindQuery {
  @ApiPropertyOptional({
    description: 'The page number for pagination',
    example: '1',
  })
  @IsOptional()
  page?: string;

  @ApiPropertyOptional({
    description: 'The number of items to return per page',
    example: '10',
  })
  @IsOptional()
  limit?: string;
}

export interface IAuthUser {
  _id: string;
  role: string;
  fcm?: string;
  passwordChangedAt?: Date;
  email?: string;
  name?: string;
}
