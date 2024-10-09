import { z } from 'zod'

const CreateUserValidationSchema = z.object({
  body: z.object({
    name: z.string({ required_error: 'Name is required.' }),
    email: z.string({ required_error: 'Email is required.' }).email({ message: 'Invalid email format.' }),
    profileImg: z.string().optional(),
    password: z
      .string({ required_error: 'Password is required' })
      .min(6, { message: 'Password must be at least 6 characters long.' }),
    role: z.enum(['admin', 'user']).default('user'),
    status: z.enum(['active', 'blocked']).default('active'),
    isDeleted: z.boolean().default(false)
  })
})

// export type UserValidationSchema = z.infer<typeof UserValidationSchema>;

export const UserValidations = { CreateUserValidationSchema }
