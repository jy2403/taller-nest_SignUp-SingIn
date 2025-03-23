import { Injectable, UnauthorizedException } from '@nestjs/common';
import * as nodemailer from 'nodemailer';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { User, UserServiceInterface } from './interfaces/user.interface';
import {
  CreateUserDto,
  UpdateUserDto,
  LoginDto,
  ChangePasswordDto,
} from './dto/user.dto';
import { InjectModel } from '@nestjs/mongoose';
import { UserDocument, UserModel } from './schemas/user.schema';
import { Model } from 'mongoose';

@Injectable()
export class UserService implements UserServiceInterface {
  private transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    secure: false,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  constructor(
    @InjectModel(UserModel.name) private userModel: Model<UserDocument>,
    private jwtService: JwtService,
  ) {}

  async create(createUserDto: CreateUserDto): Promise<User> {
    const existUser = await this.userModel.findOne({
      email: createUserDto.email,
    });
    if (existUser) {
      throw new Error('El email ya existe');
    }
    const hashedPassword = await bcrypt.hash(createUserDto.password, 10);
    const verificationCode = Math.floor(
      100000 + Math.random() * 900000,
    ).toString();

    const newUser = new this.userModel({
      ...createUserDto,
      password: hashedPassword,
      verificationCode: verificationCode,
      verificationCodeExpires: Date.now() + 24 * 60 * 60 * 1000,
    });
    const savedUser = await newUser.save();
    await this.sendVerificationEmail(createUserDto.email, verificationCode);
    return this.mapToUserInterface(savedUser.toObject());
  }

  async findAll(): Promise<User[]> {
    const users = await this.userModel.find().lean().exec();
    return users.map((user) => this.mapToUserInterface(user));
  }

  async findOne(id: string): Promise<User> {
    const user = this.userModel.findById(id).lean().exec();
    if (!user) {
      throw new Error('usuario con ID ${id} no encontrado');
    }
    return this.mapToUserInterface(user);
  }

  async findByEmail(email: string): Promise<User> {
    const user = this.userModel.findOne({ email: email }).lean().exec();
    if (!user) {
      throw new Error('usuario con email ${email} no encontrado');
    }
    return this.mapToUserInterface(user);
  }

  async update(id: string, updateUserDto: UpdateUserDto): Promise<User> {
    const updatedUser = this.userModel
      .findByIdAndUpdate(id, updateUserDto, { new: true })
      .lean()
      .exec();
    if (!updatedUser) {
      throw new Error('usuario con ID ${id} no encontrado');
    }
    return this.mapToUserInterface(updatedUser);
  }

  async remove(id: string): Promise<void> {
    const result = this.userModel.findByIdAndDelete(id).exec();
    if (!result) {
      throw new Error('usuario con ID ${id} no encontrado');
    }
  }

  async verifyUser(id: string, verificationCode: string): Promise<User> {
    const user = await this.userModel.findById(id);
    if (!user) throw new Error(`Usuario con ID ${id} no encontrado`);

    if (user.verificationCode !== verificationCode) {
      throw new Error('Código de verificación incorrecto'); // Mensaje seguro
    }

    const updatedUser = await this.userModel.findByIdAndUpdate(
      id,
      { isVerified: true },
      { new: true },
    );

    return this.mapToUserInterface(updatedUser);
  }

  async login(
    loginDto: LoginDto,
  ): Promise<{ accessToken: string; refreshToken: string; user: User }> {
    const user = await this.userModel.findOne({ email: loginDto.email });
    if (!user) throw new UnauthorizedException('credenciales inválidas');

    const isPasswordCorrect = await bcrypt.compare(
      loginDto.password,
      user.password,
    );
    if (!isPasswordCorrect)
      throw new UnauthorizedException('credenciales inválidas');

    if (!user.isVerified)
      throw new UnauthorizedException('usuario no verificado');

    const accessToken = this.jwtService.sign({ id: user.id });
    const refreshToken = this.jwtService.sign(
      { id: user.id },
      { expiresIn: '7d' },
    );
    user.refreshToken = refreshToken;
    await user.save();
    return { accessToken, refreshToken, user: this.mapToUserInterface(user) };
  }

  async refreshToken(
    refreshToken: string,
  ): Promise<{ accessToken: string; refreshToken: string }> {
    const verifiedtoken = this.jwtService.verify(refreshToken);
    const user = await this.userModel.findById(verifiedtoken.id).lean().exec();

    if (user.refreshToken != refreshToken) {
      throw new UnauthorizedException(
        'token no válido1' + user.refreshToken + refreshToken,
      );
    }

    const newaccessToken = this.jwtService.sign({ id: user.id });
    const newrefreshToken = this.jwtService.sign(
      { id: user.id },
      { expiresIn: '7d' },
    );
    user.refreshToken = refreshToken;
    return { accessToken: newaccessToken, refreshToken: newrefreshToken };
  }

  async changePassword(
    id: string,
    changePasswordDto: ChangePasswordDto,
  ): Promise<void> {
    const user = await this.userModel.findById(id);
    const isPasswordCorrect = await bcrypt.compare(
      changePasswordDto.currentPassword,
      user.password,
    );
    if (!isPasswordCorrect)
      throw new UnauthorizedException('contraseña actual incorrecta');

    user.password = await bcrypt.hash(changePasswordDto.newPassword, 10);
    await user.save();
  }

  private async sendVerificationEmail(email: string, verificationCode: string) {
    await this.transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Verifica tu cuenta',
      html: `
      <h1>Gracias por registrarte</h1>
      <h1>tu código de verificación es: <strong>${verificationCode}</Strong><h1>
      `,
    });
  }
  private mapToUserInterface(UserDoc: any): User {
    return {
      id: UserDoc._id ? UserDoc._id.toString() : UserDoc.id,
      name: UserDoc.name,
      email: UserDoc.email,
      isVerified: UserDoc.isVerified,
      role: UserDoc.role,
      refreshToken: UserDoc.refreshToken,
      createdAt: UserDoc.createdAt,
      updatedAt: UserDoc.updatedAt,
    };
  }
}
