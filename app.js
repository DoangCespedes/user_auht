import express from 'express';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken'
import cookieParser from 'cookie-parser';
import cors from 'cors'
import { UserRepository } from './user-repository.js'
// import { UserRepository } from './user-repository';

dotenv.config();

const port = process.env.PORT || 3000; // Valor por defecto si no está configurado en .env
const secret = process.env.SECRET_JWT_KEY

const app = express();

// Middleware para err CORS
app.use( cors()) ;

// Middleware para parsear JSON
app.use(express.json());
app.use(cookieParser())

app.get('/', (req, res) => {
    res.send('hello world');
});

app.post('/login', async (req, res) => {
    const { userName, password } = req.body; // Asegúrate de desestructurar correctamente

    
    try {
        const user = await UserRepository.login({ userName, password });
        const token = jwt.sign(
            { id: user._id, userName: user.userName},
            secret, 
            {
                expiresIn:'1h'
            }
        )
        res
        .cookie('access_token', token, {
            httpOnly: true, //la cookie solo se puede acceder desde el servidor
            secure: process.env.NODE_ENV === 'PRODUCTION', // la cookie solo se puede acceder por https
            sameSite: 'strict', //lacookie solo se puede acceder en el mismo dominio
            maxAge: 1000 * 60 * 60 // la cookie solo va a tener valides una hora
        })
        .json({ user, token }); // Devuelve la respuesta en formato JSON
    } catch (error) {
        res.status(401).json({ error: error.message }); // Enviar la respuesta de error como JSON
    }
});


app.post('/register', async(req, res) => {
    const { userName, password } = req.body;
    console.log(req.body);

    try {
        const id = await UserRepository.create({ userName, password });
        res.send({ id });
    } catch (error) {
        res.status(400).json({ error: error.message }); // Enviar respuesta de error como JSON
    }
});

app.post('/logout', (req, res) => {
    // Implementar la lógica de logout aquí
    res.send('Logout endpoint');
});

app.get('/protected', (req, res) => {

    const token = req.cookies.access_token

    if (!token) {
        res.status(403).send('Acces not authorized')
    }

    try {
        const data = jwt.verify(token, secret)
        res.json({ message: 'Protected', data });
    } catch (error) {
        res.status(401).send('Acces not authorized')
    }

});


app.listen(port, () => {
    console.log('Server running on port', port);
});
