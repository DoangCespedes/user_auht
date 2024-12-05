import crypto from 'node:crypto';

import dbLocal from "db-local";
import bcrypt from "bcrypt"
import dotenv from 'dotenv';
dotenv.config(); 


const salt = parseInt(process.env.SALT_ROUNDS);

// if (!salt) {
//     throw new Error('SALT_ROUNDS is not defined or invalid');
// }

const { Schema } = new dbLocal({ path: './db' });

const User = Schema('User', {
    _id: { type: String, required: true },
    userName: { type: String, required: true },
    password: { type: String, required: true },
});

export class UserRepository {
    static async create({ userName, password }) {
        // 1. Validaciones de username (opcional: usar zod)
        Validation.userName(userName)
        Validation.password(password)
        // 2. Asegurarse de que el UserName no existe
        const user = User.findOne({ userName });
        if (user) throw new Error('Username already exists');

        const id = crypto.randomUUID();
        const hashedPassword = await bcrypt.hash(password, salt )

        User.create({
            _id: id,
            userName,
            password: hashedPassword
        }).save();

        return id;
    }

    static async login({ userName, password }) {
        // Validación de los inputs
        Validation.userName(userName);
        Validation.password(password);
    
        // Validamos si el usuario no existe (asegúrate de que User.findOne es asíncrono o síncrono)
        const user = await User.findOne({ userName }); // Agrega `await` si findOne es asíncrono
        if (!user) throw new Error('Username does not exist');
    
        // Validamos si el password hasheado es el mismo (usa `bcrypt.compare`)
        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) throw new Error('Password is invalid');
    
        const { password: _, ...publicUser } = user// de esta manera omitimos el campo que no queremeos devolver

        return publicUser;
    }
    
}



class Validation {
    static userName(userName) {
        if (typeof userName !== 'string') throw new Error('Username must be a string');
        if (userName.length < 3) throw new Error('Username must be at least 3 characters long');

    }

    static password(password){
        if (typeof password !== 'string') throw new Error('Password must be a string');
        if (password.length < 3) throw new Error('Password must be at least 3 characters long');

    }
}
