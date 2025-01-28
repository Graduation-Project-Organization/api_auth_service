import { SetMetadata } from '@nestjs/common';
import { All_Role } from '../enum';
export const Roles = (...roles: All_Role[]) => SetMetadata('roles', roles);
