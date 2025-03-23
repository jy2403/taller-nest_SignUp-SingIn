import {
  Body,
  Controller,
  Post,
  Param,
  Patch,
  UseGuards,
  Get,
  Delete,
} from '@nestjs/common';
import { UserService } from './user.service';
import {
  CreateUserDto,
  LoginDto,
  ChangePasswordDto,
  RefreshTokenDto,
  UpdateUserDto,
} from './dto/user.dto';
import { AuthGuard } from '@nestjs/passport';

@Controller('api/v1/users')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Post('register')
  async register(@Body() createUserDto: CreateUserDto) {
    return this.userService.create(createUserDto);
  }

  @Post('login')
  async login(@Body() loginDto: LoginDto) {
    return this.userService.login(loginDto);
  }

  @Post('refresh-token')
  async refreshToken(@Body() refreshTokenDto: RefreshTokenDto) {
    return this.userService.refreshToken(refreshTokenDto.refreshToken);
  }

  @Post('verify/:id/:verificationCode')
  async verifyUser(
    @Param('id') id: string,
    @Param('verificationCode') verificationCode: string,
  ) {
    return this.userService.verifyUser(id, verificationCode);
  }

  @Patch('change-password/:id')
  @UseGuards(AuthGuard('jwt'))
  async changePassword(
    @Param('id') id: string,
    @Body() changePasswordDto: ChangePasswordDto,
  ) {
    return this.userService.changePassword(id, changePasswordDto);
  }

  @Get('all')
  async findAll() {
    return this.userService.findAll();
  }
  @Get('findOne/:id')
  async findOne(@Param('id') id: string) {
    return this.userService.findOne(id);
  }
  @Get('findByEmail/:email')
  async findByEmail(@Param('email') email: string) {
    return this.userService.findByEmail(email);
  }
  @Patch('update/:id')
  async update(@Param('id') id: string, @Body() updateUserDto: UpdateUserDto) {
    return this.userService.update(id, updateUserDto);
  }
  @Delete('delete/:id')
  async delete(@Param('id') id: string) {
    return this.userService.remove(id);
  }
}
