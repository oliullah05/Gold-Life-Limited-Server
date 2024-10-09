/* eslint-disable no-undef */
/* eslint-disable no-console */
/* eslint-disable @typescript-eslint/no-explicit-any */
import fs from 'fs'

export const fileRemover = async (file: any) => {
  const path = file?.path
  fs.unlink(path, (err) => {
    if (err) {
      console.log(err)
    } else {
      console.log('File is deleted.')
    }
  })
}
