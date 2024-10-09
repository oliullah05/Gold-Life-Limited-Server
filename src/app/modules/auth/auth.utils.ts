import jwt, { JwtPayload } from 'jsonwebtoken'
import { ObjectId } from 'mongodb'

export const createToken = (jwtPayload: { userId: ObjectId; role: string }, secret: string, expiresIn: string) => {
  return jwt.sign(jwtPayload, secret, {
    expiresIn
  })
}

export const verifyToken = (token: string, secret: string) => {
  return jwt.verify(token, secret) as JwtPayload
}
