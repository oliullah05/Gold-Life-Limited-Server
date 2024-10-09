import bcrypt from 'bcrypt'

const isPasswordMatched = async (plainTextPassword: string, hashedPassword: string) => {
  return await bcrypt.compare(plainTextPassword, hashedPassword)
}

export default isPasswordMatched
