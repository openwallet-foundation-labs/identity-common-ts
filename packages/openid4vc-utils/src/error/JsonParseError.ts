import { Openid4vcBaseError } from './Openid4vcBaseError'

export class JsonParseError extends Openid4vcBaseError {
  public constructor(message: string, jsonString: string) {
    super(`${message}\n${jsonString}`)
  }
}
