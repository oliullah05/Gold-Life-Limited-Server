
import cookieParser from 'cookie-parser'
import cors from 'cors'
import express, { Application, Request, Response } from 'express'
import router from './app/routes'
import globalErrorHandler from './app/middlewares/globalErrorhandler'
import notFound from './app/middlewares/notFound'

const app: Application = express()

//parsers
app.use(express.json())
app.use(cookieParser())

app.use(cors({ origin: ['*'], credentials: true }))

// application routes
app.use('/api/v1', router)

app.get('/', (req: Request, res: Response) => {
  res.json({
    message: 'Gold Life Limited Server is running!'
  })
})

app.use(globalErrorHandler)

// Not Found
app.use(notFound)

export default app
