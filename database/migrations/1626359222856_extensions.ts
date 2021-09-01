import BaseSchema from '@ioc:Adonis/Lucid/Schema'

export default class ExtensionsSchema extends BaseSchema {
  protected tableName = 'users'

  public async up() {
    await this.db.rawQuery('CREATE EXTENSION IF NOT EXISTS "uuid-ossp";').knexQuery
    await this.db.rawQuery('CREATE EXTENSION IF NOT EXISTS "unaccent";').knexQuery
  }

  public async down() {}
}
