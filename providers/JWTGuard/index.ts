import {
  DatabaseTokenProviderConfig,
  GetProviderRealUser,
  GuardContract,
  GuardsList,
  ProvidersList,
  ProviderTokenContract,
  TokenProviderContract,
  UserProviderContract,
  RedisTokenProviderConfig,
} from '@ioc:Adonis/Addons/Auth'
import { BaseGuard } from '@adonisjs/auth/build/src/Guards/Base'
import { DateTime } from 'luxon'
import { EmitterContract } from '@ioc:Adonis/Core/Event'
import { HttpContextContract } from '@ioc:Adonis/Core/HttpContext'
import { string, base64 } from '@poppinss/utils/build/helpers'
import { createHash, createSecretKey, KeyObject } from 'crypto'
import { ProviderToken } from '@adonisjs/auth/build/src/Tokens/ProviderToken'
import { SignJWT } from 'jose/jwt/sign'
import { jwtVerify } from 'jose/jwt/verify'
import { AuthenticationException } from '@adonisjs/auth/build/standalone'

/**
 * Login options
 */
export type JWTLoginOptions = {
  name?: string
  expiresIn?: number | string
} & { [key: string]: any }

/**
 * Shape of JWT guard config.
 */
export type JWTGuardConfig<Provider extends keyof ProvidersList> = {
  /**
   * Driver name is always constant
   */
  driver: 'jwt'

  /**
   * Issuer name to sign the token
   */
  issuer: string

  /**
   * Audience to sign the token
   */
  audience: string

  /**
   * Public key to sign the token
   */
  publicKey: string

  /**
   * Private key to sign the token
   */
  privateKey: string

  /**
   * Provider for managing tokens
   */
  tokenProvider: DatabaseTokenProviderConfig | RedisTokenProviderConfig

  /**
   * User provider
   */
  provider: ProvidersList[Provider]['config']
}

/**
 * JWT token is generated during the login call by the JWTGuard.
 */
export interface JWTTokenContract<User extends any> {
  /**
   * Always a bearer token
   */
  type: 'bearer'

  /**
   * The user for which the token was generated
   */
  user: User

  /**
   * Date/time when the token will be expired
   */
  expiresAt?: DateTime

  /**
   * Time in seconds until the token is valid
   */
  expiresIn?: number

  /**
   * Any meta-data attached with the token
   */
  meta: any

  /**
   * Token name
   */
  name: string

  /**
   * Token public value
   */
  accessToken: string

  /**
   * Token public value
   */
  refreshToken: string

  /**
   * Token hash (persisted to the db as well)
   */
  tokenHash: string

  /**
   * Serialize token
   */
  toJSON(): {
    type: 'bearer'
    accessToken: string
    refreshToken: string
    expires_at?: string
    expires_in?: number
  }
}

/**
 * JWT token represents a persisted token generated for a given user.
 *
 * Calling `token.toJSON()` will give you an object, that you can send back
 * as response to share the token with the client.
 */
export class JWTToken implements JWTTokenContract<any> {
  /**
   * The type of the token. Always set to bearer
   */
  public type = 'bearer' as const

  /**
   * The datetime in which the token will expire
   */
  public expiresAt?: DateTime

  /**
   * Time left until token gets expired
   */
  public expiresIn?: number

  /**
   * Any meta data attached to the token
   */
  public meta: any

  /**
   * Hash of the token saved inside the database. Make sure to never share
   * this with the client
   */
  public tokenHash: string

  constructor(
    public name: string, // Name associated with the token
    public accessToken: string, // The raw token value. Only available for the first time
    public refreshToken: string, // The raw refresh token value. Only available for the first time
    public user: any // The user for which the token is generated
  ) {}

  /**
   * Shareable version of the token
   */
  public toJSON() {
    return {
      type: this.type,
      accessToken: this.accessToken,
      refreshToken: this.refreshToken,
      ...(this.expiresAt ? { expires_at: this.expiresAt.toISO() || undefined } : {}),
      ...(this.expiresIn ? { expires_in: this.expiresIn } : {}),
    }
  }
}

/**
 * Shape of the JWT guard
 */
export interface JWTGuardContract<
  Provider extends keyof ProvidersList,
  Name extends keyof GuardsList
> extends GuardContract<Provider, Name> {
  token?: ProviderTokenContract
  tokenProvider: TokenProviderContract

  /**
   * Attempt to verify user credentials and perform login
   */
  attempt(
    uid: string,
    password: string,
    options?: JWTLoginOptions
  ): Promise<JWTTokenContract<GetProviderRealUser<Provider>>>

  /**
   * Login a user without any verification
   */
  login(
    user: GetProviderRealUser<Provider>,
    options?: JWTLoginOptions
  ): Promise<JWTTokenContract<GetProviderRealUser<Provider>>>

  /**
   * Generate token for a user without any verification
   */
  generate(
    user: GetProviderRealUser<Provider>,
    options?: JWTLoginOptions
  ): Promise<JWTTokenContract<GetProviderRealUser<Provider>>>

  /**
   * Alias for logout
   */
  revoke(): Promise<void>

  /**
   * Login a user using their id
   */
  loginViaId(
    id: string | number,
    options?: JWTLoginOptions
  ): Promise<JWTTokenContract<GetProviderRealUser<Provider>>>
}

/**
 * Exposes the API to generate and authenticate HTTP request using jwt tokens
 */
export class JWTGuard extends BaseGuard<any> implements JWTGuardContract<any, any> {
  /**
   * Token fetched as part of the authenticate or the login
   * call
   */
  public token?: ProviderTokenContract

  /**
   * Reference to the parsed token
   */
  private parsedToken?: {
    value: string
    tokenId: string
  }

  /**
   * Token type for the persistance store
   */
  private tokenType = this.config.tokenProvider.type || 'jwt_token'

  /**
   * constructor of class.
   */
  constructor(
    name: string,
    public config: JWTGuardConfig<any>,
    private emitter: EmitterContract,
    provider: UserProviderContract<any>,
    private ctx: HttpContextContract,
    public tokenProvider: TokenProviderContract
  ) {
    super(name, config, provider)
  }

  /**
   * Verify user credentials and perform login
   */
  public async attempt(uid: string, password: string, options?: JWTLoginOptions): Promise<any> {
    const user = await this.verifyCredentials(uid, password)
    return this.login(user, options)
  }

  /**
   * Same as [[authenticate]] but returns a boolean over raising exceptions
   */
  public async check(): Promise<boolean> {
    try {
      await this.authenticate()
    } catch (error) {
      /**
       * Throw error when it is not an instance of the authentication
       */
      if (!(error instanceof AuthenticationException)) {
        throw error
      }

      this.ctx.logger.trace(error, 'Authentication failure')
    }

    return this.isAuthenticated
  }

  /**
   * Authenticates the current HTTP request by checking for the bearer token
   */
  public async authenticate(): Promise<GetProviderRealUser<any>> {
    /**
     * Return early when authentication has already attempted for
     * the current request
     */
    if (this.authenticationAttempted) {
      return this.user
    }

    this.authenticationAttempted = true

    /**
     * Ensure the "Authorization" header value exists
     */
    const token = this.getBearerToken()
    const { tokenId, value } = this.parsePublicToken(token)

    /**
     * Query token and user
     */
    const providerToken = await this.getProviderToken(tokenId, value)
    const providerUser = await this.getUserById(providerToken.userId)

    /**
     * Marking user as logged in
     */
    this.markUserAsLoggedIn(providerUser.user, true)
    this.token = providerToken

    /**
     * Emit authenticate event. It can be used to track user logins.
     */
    this.emitter.emit(
      'adonis:api:authenticate',
      this.getAuthenticateEventData(providerUser.user, this.token)
    )

    return providerUser.user
  }

  /**
   * Generate token for a user. It is merely an alias for `login`
   */
  public async generate(user: any, options?: JWTLoginOptions): Promise<JWTTokenContract<any>> {
    return this.login(user, options)
  }

  /**
   * Login user using their id
   */
  public async loginViaId(id: string | number, options?: JWTLoginOptions): Promise<any> {
    const providerUser = await this.findById(id)
    return this.login(providerUser.user, options)
  }

  /**
   * Login a user
   */
  public async login(user: GetProviderRealUser<any>, options?: JWTLoginOptions): Promise<any> {
    /**
     * Normalize options with defaults
     */
    let { expiresIn, name, payload, ...meta } = Object.assign({ name: 'JWT Access Token' }, options)

    /**
     * Since the login method is not exposed to the end user, we cannot expect
     * them to instantiate and pass an instance of provider user, so we
     * create one manually.
     */
    const providerUser = await this.getUserForLogin(user, this.config.provider.identifierKey)

    /**
     * "getUserForLogin" raises exception when id is missing, so we can
     * safely assume it is defined
     */
    const id = providerUser.getId()!
    const token = await this.generateTokenForPersistance(expiresIn, {
      ...payload,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
      },
    })

    /**
     * Persist token to the database. Make sure that we are always
     * passing the hash to the storage driver
     */
    const providerToken = new ProviderToken(name, token.accessTokenHash, id, this.tokenType)
    providerToken.expiresAt = token.expiresAt
    meta.refreshToken = token.refreshTokenHash
    providerToken.meta = meta
    const tokenId = await this.tokenProvider.write(providerToken)

    /**
     * Construct a new API Token instance
     */
    const apiToken = new JWTToken(
      name,
      `${base64.urlEncode(tokenId)}.${token.accessToken}`,
      `${base64.urlEncode(tokenId)}.${token.refreshToken}`,
      providerUser.user
    )
    apiToken.tokenHash = token.accessTokenHash
    apiToken.expiresAt = token.expiresAt
    apiToken.meta = meta

    /**
     * Marking user as logged in
     */
    this.markUserAsLoggedIn(providerUser.user)
    this.token = providerToken

    /**
     * Emit login event. It can be used to track user logins.
     */
    this.emitter.emit('adonis:api:login', this.getLoginEventData(providerUser.user, apiToken))

    return apiToken
  }

  /**
   * Logout by removing the token from the storage
   */
  public async logout(_options?: JWTLoginOptions): Promise<void> {
    if (!this.authenticationAttempted) {
      await this.check()
    }

    /**
     * Clean up token from storage
     */
    if (this.parsedToken) {
      await this.tokenProvider.destroy(this.parsedToken.tokenId, this.tokenType)
    }

    this.markUserAsLoggedOut()
  }

  /**
   * Alias for the logout method
   */
  public revoke(): Promise<void> {
    return this.logout()
  }

  /**
   * Serialize toJSON for JSON.stringify
   */
  public toJSON(): any {
    return {
      isLoggedIn: this.isLoggedIn,
      isGuest: this.isGuest,
      authenticationAttempted: this.authenticationAttempted,
      isAuthenticated: this.isAuthenticated,
      user: this.user,
    }
  }

  /**
   * Generates a new access token + refresh token + hash's for the persistance.
   */
  private async generateTokenForPersistance(expiresIn?: string | number, payload: any = {}) {
    let builder = new SignJWT({ data: payload })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt()
      .setIssuer(this.config.issuer)
      .setAudience(this.config.audience)

    if (expiresIn) {
      builder = builder.setExpirationTime(expiresIn)
    }

    const accessToken = await builder.sign(this.generateKey(this.config.privateKey))
    const accessTokenHash = this.generateHash(accessToken)

    const refreshToken = await new SignJWT({ data: accessTokenHash })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt()
      .setIssuer(this.config.issuer)
      .setAudience(this.config.audience)
      .sign(this.generateKey(this.config.privateKey))

    return {
      accessToken,
      accessTokenHash,
      refreshToken,
      refreshTokenHash: this.generateHash(refreshToken),
      expiresAt: this.getExpiresAtDate(expiresIn),
    }
  }

  /**
   * Converts key string to Buffer
   */
  private generateKey(hash: string): KeyObject {
    return createSecretKey(Buffer.from(hash, 'hex'))
  }

  /**
   * Converts value to a sha256 hash
   */
  private generateHash(token: string) {
    return createHash('sha256').update(token).digest('hex')
  }

  /**
   * Converts expiry duration to an absolute date/time value
   */
  private getExpiresAtDate(expiresIn?: string | number) {
    if (!expiresIn) {
      return
    }

    const milliseconds = typeof expiresIn === 'string' ? string.toMs(expiresIn) : expiresIn
    return DateTime.local().plus({ milliseconds })
  }

  /**
   * Returns the bearer token
   */
  private getBearerToken(): string {
    /**
     * Ensure the "Authorization" header value exists
     */
    const token = this.ctx.request.header('Authorization')
    if (!token) {
      throw AuthenticationException.invalidToken(this.name)
    }

    /**
     * Ensure that token has minimum of two parts and the first
     * part is a constant string named `bearer`
     */
    const [type, value] = token.split(' ')
    if (!type || type.toLowerCase() !== 'bearer' || !value) {
      throw AuthenticationException.invalidToken(this.name)
    }

    return value
  }

  /**
   * Parses the token received in the request. The method also performs
   * some initial level of sanity checks.
   */
  private parsePublicToken(token: string) {
    const parts = token.split('.')

    /**
     * Ensure the token has two parts
     */
    if (parts.length !== 4) {
      throw AuthenticationException.invalidToken(this.name)
    }

    /**
     * Ensure the first part is a base64 encode id
     */
    const tokenId = base64.urlDecode(parts.splice(0, 1)[0], undefined, true)
    if (!tokenId) {
      throw AuthenticationException.invalidToken(this.name)
    }

    /**
     * Ensure 2nd part of the token has the expected length
     */
    const value = parts.join('.')
    if (value.length < 30) {
      throw AuthenticationException.invalidToken(this.name)
    }

    /**
     * Set parsed token
     */
    this.parsedToken = { tokenId, value }

    return this.parsedToken
  }

  /**
   * Returns the token by reading it from the token provider
   */
  private async getProviderToken(tokenId: string, value: string): Promise<ProviderTokenContract> {
    const providerToken = await this.tokenProvider.read(
      tokenId,
      this.generateHash(value),
      this.tokenType
    )

    if (!providerToken) {
      throw AuthenticationException.invalidToken(this.name)
    }

    return providerToken
  }

  /**
   * Returns user from the user session id
   */
  private async getUserById(id: string | number) {
    const token = this.parsedToken?.value || ''
    const secret = this.generateKey(this.config.privateKey)

    const { payload } = await jwtVerify(token, secret, {
      issuer: this.config.issuer,
      audience: this.config.audience,
    })

    const { data, exp }: any = payload

    if (exp && exp < Math.floor(DateTime.now().toSeconds())) {
      throw AuthenticationException.invalidToken(this.name)
    }

    if (!data || !data.user || !data.user.id || !data.user.name || !data.user.email) {
      throw AuthenticationException.invalidToken(this.name)
    }

    if (data.user.id !== id) {
      throw AuthenticationException.invalidToken(this.name)
    }

    const authenticatable = await this.provider.getUserFor(data.user)

    if (!authenticatable.user) {
      throw AuthenticationException.invalidToken(this.name)
    }

    return authenticatable
  }

  /**
   * Returns data packet for the login event. Arguments are
   *
   * - The mapping identifier
   * - Logged in user
   * - HTTP context
   * - API token
   */
  private getLoginEventData(user: any, token: JWTTokenContract<any>): any {
    return {
      name: this.name,
      ctx: this.ctx,
      user,
      token,
    }
  }

  /**
   * Returns data packet for the authenticate event. Arguments are
   *
   * - The mapping identifier
   * - Logged in user
   * - HTTP context
   * - A boolean to tell if logged in viaRemember or not
   */
  private getAuthenticateEventData(user: any, token: ProviderTokenContract): any {
    return {
      name: this.name,
      ctx: this.ctx,
      user,
      token,
    }
  }
}
