import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Patch,
  Post,
  Query,
  UseGuards,
} from '@nestjs/common';
import { AuthenticationGuard } from '../../common/guard/authentication.guard';
import { AuthorizationGuard } from '../../common/guard/authorization.guard';
import { Roles } from '../../common/decorator/roles';
import { All_Role } from '../../common/enum';
import { ValidateObjectIdPipe } from '../../common/pipe/validate.mongo.pipe';
import { QueryUserDto } from '../dto/query.user.dto';
import { UpdateUserDto } from '../dto/update.user.dto';
import { CreateUserDto } from '../dto/create.user.dto';
import { UserService } from '../service/user.service';

@Controller('admin')
export class AdminController {
  constructor(private readonly userService: UserService) {}
  @Get(':userId')
  @UseGuards(AuthenticationGuard, AuthorizationGuard)
  @Roles(All_Role.Admin)
  getUser(@Param('userId', ValidateObjectIdPipe) adminId: string) {
    return this.userService.getOneUser(adminId);
  }
  @Get()
  @UseGuards(AuthenticationGuard, AuthorizationGuard)
  @Roles(All_Role.Admin)
  getAllUsers(@Query() query: QueryUserDto) {
    return this.userService.getAllUsers(query);
  }
  @Post()
  @UseGuards(AuthenticationGuard, AuthorizationGuard)
  @Roles(All_Role.Admin)
  // @UseInterceptors(FileInterceptor('icon'))
  createUser(
    @Body() body: CreateUserDto,
    // @UploadedFile() file: Express.Multer.File,
  ) {
    return this.userService.createUser(body);
  }
  @Delete(':userId')
  @UseGuards(AuthenticationGuard, AuthorizationGuard)
  @Roles(All_Role.Admin)
  deleteUser(@Param('userId', ValidateObjectIdPipe) userId: string) {
    return this.userService.deleteUser(userId);
  }
  @Patch(':userId')
  @UseGuards(AuthenticationGuard, AuthorizationGuard)
  @Roles(All_Role.Admin)
  // @UseInterceptors(FileInterceptor('icon'))
  updateUser(
    @Param('userId', ValidateObjectIdPipe) userId: string,
    @Body() body: UpdateUserDto,
    // @UploadedFile() file: Express.Multer.File,
  ) {
    return this.userService.updateUser(userId, body);
  }
}
