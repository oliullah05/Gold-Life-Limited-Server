import { ZodError, ZodIssue } from 'zod'
import { TErrorSources, TGenericErrorResponse } from '../interface/error'

const handleZodError = (err: ZodError): TGenericErrorResponse => {
  let messages = ''
  const errorSources: TErrorSources = err.issues.map((issue: ZodIssue) => {
    messages = messages + issue.message + ' '
    return {
      path: issue?.path[issue.path.length - 1],
      message: issue.message
    }
  })

  const statusCode = 400

  return {
    statusCode,
    message: messages.trim() || 'Validation Error',
    errorSources
  }
}

export default handleZodError
