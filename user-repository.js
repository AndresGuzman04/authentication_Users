import DBLocal from 'db-local'
import bcrypt from 'bcrypt'

import crypto from 'node:crypto'
import { SALT_ROUNDS } from './config.js'

const { Schema } = new DBLocal({ path: './db' })

const User = Schema('User', {
  _id: { type: String, required: true },
  username: { type: String, required: true },
  password: { type: String, required: true }
})

export class UserRepository {
  static async create ({ username, password }) {
    // Validate username (optinonal use zod)
    validation.validateUsername(username)
    // Validate password (optional use zod)
    validation.validatePassword(password)

    // validate username exists?
    const existingUser = User.findOne({ username })
    if (existingUser) throw new Error('Username already exists')
    // create user
    const id = crypto.randomUUID()
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS)

    User.create({
      _id: id,
      username,
      password: hashedPassword
    }).save()
    return id
  }

  static async login ({ username, password }) {
    // Validate username (optinonal use zod)
    validation.validateUsername(username)
    // Validate password (optional use zod)
    validation.validatePassword(password)

    const user = User.findOne({ username })
    if (!user) throw new Error('Invalid username or password')
    const isValidPassword = await bcrypt.compare(password, user.password)
    if (!isValidPassword) throw new Error('Invalid username or password')

    // version for public or private
    // const public = {
    //   username: user.username,
    // }

    const { password: _, ...publicUser } = user

    return publicUser
  }
}

class validation {
  static validateUsername (username) {
    if (typeof username !== 'string') throw new Error('Username must be a string')
    if (username.length < 3) throw new Error('Userame must be at least 3 characters long')
  }

  static validatePassword (password) {
    if (typeof password !== 'string') throw new Error('Password must be a string')
    if (password.length < 6) throw new Error('Password must be at least 6 characters long')
  }
}
