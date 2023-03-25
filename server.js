require("dotenv").config();
const express = require("express")
const jwt = require("jsonwebtoken")
const bcrypt = require("bcrypt")
const bodyParser = require("body-parser")
const cors = require("cors")
const app = express()
const { v4: uuidv4 } = require('uuid');
app.use(bodyParser.json())

const users = [];

const JWT_SECRET = process.env.JWT_SECRET


app.use(express.static("public"))
app.use(
    cors({
        origin: 'http://localhost:3002'
    })
)

app.get("/usuarios", (req,res) => {
    if (users.length === 0) {
        return res.status(404).json({message: "No hay usuarios"})
    }

    res.json(users)
})

app.post("/usuarios", async (req, res) => {
    try {
        const {username, email, password} = req.body

        const existeUsuario = users.find(user => user.username === username)
        if (existeUsuario){
            return res.status(409).json({message: "El usuario ya existe"})
        }

        const existeEmail = users.find(user => user.email === email)
        if(existeEmail) {
            return res.status(409).json({message: "El email ya está registrado"})
        }


        //ENCRIPTAR CONTRASEÑA
        const salt = await bcrypt.genSalt(10)
        const passwordEncriptado = await bcrypt.hash(password, salt)

        //Agrega usuario a lista de usuarios
        const user = {
            userId: uuidv4(),
            username: username,
            password: passwordEncriptado,
            email: email
          };
      
          // Agregamos el usuario al array
          users.push(user);


        console.log(`Usuario creado: nombre=${username}, email=${email}, passwordEncriptado=${passwordEncriptado}`)

        res.status(201).json({message: "Usuario creado exitosamente"})

    } catch( error) {
        console.error(error)
        res.status(500).json({message: "Error al crear el usuario"})
    }
})

app.delete("/usuarios/:userId", (req, res) => {
    let userId = req.params.userId
    const index = users.findIndex(user => user.userId == userId)
    
    if(index === -1){
        return res.status(404).json({message: "El usuario no existe"})
    }
    console.log("usuario eliminado")
    users.splice(index,1)
    res.json({message: "Usuario eliminado"})
})

app.post("/login", async (req, res) => {
    console.log(req.body)
    const {username, password} = req.body
    const user = users.find( user => user.username === username)

    if(!user){
        return res.status(401).json({error: "Credenciales invalidas"})
    }

    const match = await bcrypt.compare(password, user.password)
    if(!match){
        return res.status(401).json({error: "Credenciales invalidas"})
    }
   
    const token = jwt.sign({userId: user.userId, username: user.username, password: user.password}, JWT_SECRET, {expiresIn: "24h"})
    res.header("Authorization","Bearer " +token).json({ token })

})

app.get("/protegido",autenticar, (req, res) => {
   res.sendFile("public/protegido.html", {root: __dirname})
    
})

function autenticar(req, res, next) {
    const authHeader = req.headers.authorization
    if (!authHeader) {
        return res.status(401).json({error: "No autorizado"})
    }

    const token = authHeader.split(' ')[1] 
    
    try {
        const decodedToken =jwt.verify(token, JWT_SECRET)
        req.userId = decodedToken.userId
        console.log("Authorization", `Bearer ${token}`)
        res.header("Authorization", `Bearer ${token}`)
        next()
    } catch (error) {
        res.status(401).json({error:"Credenciales invalidas"})
    }
}

app.get("/protegido2", autenticar, (req, res) => {
    res.send("Te la bañaste x2")
})

app.listen(4000, () => {
    console.log("puerto 4000")
})