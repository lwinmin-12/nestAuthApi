import { Body, Controller, Post, Req } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('signIn')
  signIn(@Body() dto: AuthDto) {
    return this.authService.signIn(dto);
  }

  @Post('signUp')
  signUp(@Body() dto: AuthDto) {
    return this.authService.signUp(dto);
  }
}
