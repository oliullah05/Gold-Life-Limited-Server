import { Router } from 'express'
import { UserRoutes } from '../modules/user/user.route'
import { AuthRoutes } from '../modules/auth/auth.route'
import { careerRoutes } from '../modules/career/career.route'

const router = Router()

const moduleRoutes = [
  {
    path: '/user',
    route: UserRoutes
  },
  {
    path: '/auth',
    route: AuthRoutes
  },
  {
    path: '/career',
    route: careerRoutes
  }
]

moduleRoutes.forEach((route) => router.use(route.path, route.route))

export default router
