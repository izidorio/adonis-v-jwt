import User from 'App/Models/User'
import Factory from '@ioc:Adonis/Lucid/Factory'

export const UserFactory = Factory.define(User, ({ faker }) => {
  faker.locale = 'pt-BR'
  return {
    email: faker.internet.email(),
    password: faker.internet.password(),
  }
}).build()
