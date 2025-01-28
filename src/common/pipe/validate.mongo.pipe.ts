import { BadRequestException, Injectable, PipeTransform } from '@nestjs/common';

import { Types } from 'mongoose';

@Injectable()
export class ValidateObjectIdPipe implements PipeTransform {
  transform(value: string) {
    // Implement your transformation/validation logic here
    if (!value) {
      throw new BadRequestException('Felid is required');
    }

    const isValidObjectId = Types.ObjectId.isValid(value);

    if (!isValidObjectId) {
      throw new BadRequestException('Felid is not a valid ObjectId');
    }

    return value;
  }
}
