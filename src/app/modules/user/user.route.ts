/* eslint-disable @typescript-eslint/no-explicit-any */
import express, { NextFunction, Request, Response } from 'express'
import validateRequest from '../../middlewares/validateRequest'
import { upload } from '../../utils/sendImageToCloudinary'

import { UserControllers } from './user.controller'
import { UserValidations } from './user.validation'

const router = express.Router()

router.post(
  '/create-user',
  upload.single('file'),
  (req: Request, res: Response, next: NextFunction) => {
    req.body = JSON.parse(req.body.data)
    next()
  },
  validateRequest(UserValidations.CreateUserValidationSchema),
  UserControllers.createUser
)

export const UserRoutes = router
