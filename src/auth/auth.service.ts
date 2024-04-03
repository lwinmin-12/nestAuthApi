import { ForbiddenException, Injectable } from '@nestjs/common';
import { User, Bookmark } from '@prisma/client';
import { PrismaService } from 'src/prisma/prisma.service';
import * as argon from 'argon2';
import { AuthDto } from './dto';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { promises } from 'dns';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}

  async signIn(dto: AuthDto) {
    // find the user in db
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });

    if (!user) throw new ForbiddenException('Credential Error');

    const pwMatch = await argon.verify(user.hash, dto.password);

    if (!pwMatch) throw new ForbiddenException('Credential Error');

    delete user.hash;

    // return user;
    return this.signInToken(user.id, user.email);
  }

  async signUp(dto: AuthDto) {
    try {
      //hash password

      const hash = await argon.hash(dto.password);

      //save in db

      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        },
      });

      //return the save one

      delete user.hash;
      return user;
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Credentials taken');
        }
      }
      throw error;
    }
  }

  async signInToken(
    userId: number,
    email: string,
  ): Promise<{ accessToken: string }> {
    const data = { sub: userId, email };
    const secret = await this.config.get('SECRET_KEY');

    const token = await this.jwt.signAsync(data, {
      expiresIn: '15m',
      secret: secret,
    });

    return { accessToken: token };
  }
}
