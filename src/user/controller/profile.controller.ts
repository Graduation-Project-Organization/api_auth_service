import {
  Body,
  Controller,
  Delete,
  Get,
  Patch,
  // UploadedFile,
  UseGuards,
  // UseInterceptors,
} from '@nestjs/common';
import { AuthenticationGuard } from '../../common/guard/authentication.guard';
import { AuthUser } from '../../common/decorator/user.decorator';
import { IAuthUser } from '../../common/types';
// import { FileInterceptor } from '@nestjs/platform-express';
import { UpdateUserDto } from '../dto/update.user.dto';
import { ChangePasswordDto } from '../dto/change-password.user.dto';
import { UserService } from '../service/user.service';

@Controller('profile')
export class ProfileController {
  constructor(private userService: UserService) {}
  @Get()
  @UseGuards(AuthenticationGuard)
  getLoggedUser(@AuthUser() user: IAuthUser) {
    return this.userService.getOneUser(user._id);
  }
  @Patch()
  @UseGuards(AuthenticationGuard)
  updateLoggedUser(@AuthUser() user: IAuthUser, @Body() body: UpdateUserDto) {
    return this.userService.updateUser(user._id, body);
  }
  @Delete()
  @UseGuards(AuthenticationGuard)
  deleteLoggedUser(@AuthUser() user: IAuthUser) {
    return this.userService.deleteUser(user._id);
  }
  @Patch('pass')
  @UseGuards(AuthenticationGuard)
  updateLoggedAdminPassword(
    @AuthUser() user: IAuthUser,
    @Body() body: ChangePasswordDto,
  ) {
    return this.userService.changeLoggedUserPassword(body, user);
  }
}
