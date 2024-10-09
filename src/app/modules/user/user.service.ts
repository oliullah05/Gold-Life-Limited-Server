/* eslint-disable @typescript-eslint/no-explicit-any */
import AppError from '../../errors/AppError'
import { fileRemover } from '../../helpers/file/fileRemover'
import { sendImageToCloudinary } from '../../utils/sendImageToCloudinary'
import { TUser } from './user.interface'
import { User } from './user.model'

const createUser = async (file: any, payload: TUser) => {
  const isUserExists = await User.findOne({ email: payload.email })
  if (isUserExists) {
    if (file) {
      fileRemover(file)
    }
    throw new AppError(400, 'User Alrady Exits. Please Login')
  }

  // photo upload in Cloudinary
  if (file) {
    const path = file?.path
    const imageName = `${Math.random().toFixed(3).toString()} ${payload?.name}`

    //send image to cloudinary
    const { secure_url } = await sendImageToCloudinary(imageName, path)
    payload.profileImg = secure_url as string
  }

  const result = await User.create(payload)
  return result
}

export const UserServices = {
  createUser
}
