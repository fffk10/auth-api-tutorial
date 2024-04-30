import { Injectable } from '@nestjs/common'
import { PrismaService } from '@/prisma/prisma.service'
import { JwtService } from '@nestjs/jwt'
import * as bcyrpt from 'bcrypt'

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
  ) {}

  async hashPassword(password: string): Promise<string> {
    const salt = await bcyrpt.genSalt()
    return bcyrpt.hash(password, salt)
  }

  async validateUser(email: string, pass: string): Promise<any> {
    const user = await this.prisma.user.findUnique({
      where: {
        email,
      },
    })

    if (user && (await bcyrpt.compare(pass, user.password))) {
      return user
    }
    1

    return null
  }

  async login(user: any) {
    const payload = { email: user.email, sub: user.id }
    return {
      access_token: this.jwtService.sign(payload),
    }
  }
}
