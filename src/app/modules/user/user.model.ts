/* eslint-disable @typescript-eslint/no-this-alias */
import bcrypt from 'bcrypt'
import { Schema, model } from 'mongoose'
import config from '../../config'
import { UserStatus } from './user.constant'
import { TUser, UserModel } from './user.interface'

const userSchema = new Schema<TUser, UserModel>(
  {
    name: {
      type: String,
      required: [true, 'Name is required.'],
      trim:true
    },
    profileImg: {
      type: String
    },
    email: {
      type: String,
      required: [true, 'Email is required.'],
      unique: true,
      trim:true
    },
    password: {
      type: String,
      required: [true, 'Password is required.']
    },
    passwordChangedAt: {
      type: Date
    },
    role: {
      type: String,
      enum: ['admin', 'user'],
      default: 'user'
    },
    status: {
      type: String,
      enum: UserStatus,
      default: 'active'
    },
    isDeleted: {
      type: Boolean,
      default: false
    }
  },
  {
    timestamps: true
  }
)

userSchema.pre('save', async function (next) {
  const user = this // doc
  // hashing password and save into DB
  user.password = await bcrypt.hash(user.password, Number(config.bcrypt_salt_rounds))
  next()
})

userSchema.statics.isJWTIssuedBeforePasswordChanged = function (
  passwordChangedTimestamp: Date,
  jwtIssuedTimestamp: number
) {
  const passwordChangedTime = new Date(passwordChangedTimestamp).getTime() / 1000
  return passwordChangedTime > jwtIssuedTimestamp
}

export const User = model<TUser, UserModel>('User', userSchema)
