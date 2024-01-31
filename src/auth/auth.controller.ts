import { Body, Controller, Post, Req } from '@nestjs/common';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('signIn')
  signIn(@Req() req: Request) {
    console.log(req.body);
    return this.authService.signIn();
  }

  @Post('signUp')
  signUp(@Body() dto: any) {
    console.log({ dto });
    return this.authService.signUp();
  }
}
