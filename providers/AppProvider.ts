import { ApplicationContract } from '@ioc:Adonis/Core/Application'

export default class AppProvider {
  constructor(protected app: ApplicationContract) {}

  public register() {
    // Register your own bindings
  }

  public async boot() {
    // IoC container is ready
    const Auth = this.app.container.resolveBinding('Adonis/Addons/Auth')
    const { JWTGuard } = await import('./JWTGuard')

    Auth.extend('guard', 'jwt', (_auth: AuthManager, _mapping, _config, _provider, _ctx) => {
      const tokenProvider = _auth.makeTokenProviderInstance(_config.tokenProvider)
      return new JWTGuard(_mapping, _config, Event, _provider, _ctx, tokenProvider) as any
    })
  }

  public async ready() {
    // App is ready
  }

  public async shutdown() {
    // Cleanup, since app is going down
  }
}
