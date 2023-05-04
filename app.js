// imports
require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

// Express
const app = express()
const port = 3000

//Confing JSON response
app.use(express.json())


// Models
const User = require('./models/User')

// Public Route
app.get('/', (req, res) => {
  res.status(200).json({ msg: "OK" })
})

// Private Route

app.get("/user/:id", checkToken, async (req, res) => {

  const id = req.params.id
  
  const user = await User.findById(id, '-password')

  if(!user){
    return res.status(404).json({msg : 'Usuário não encontrado'})
  }

  res.json({user})
});


function checkToken (req, res, next){
  
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(" ")[1]

  if(!token){
    res.status(401).json({msg : 'Acesso negado'})
  }

  try{

    const secret = process.env.SECRET
    jwt.verify(token, secret)

    next()

  } catch(error) {
    res.status(400).json({msg : "Token inválido!"})
  }
}
  

//Registro de Usuário
app.post('/auth/register',  async (req, res) => {
  const {name, email, password, confirmpassword} = req.body
  
  if(!name){
    res.status(422).send({msg : 'Nome é obrigatório'})
  }
  if(!email){
    res.status(422).send({msg : 'Email é obrigatório'})
  }
  if(!password){
    res.status(422).send({msg : 'Senha é obrigatório'})
  }
  if(!confirmpassword){
    res.status(422).send({msg : 'Confirmação de senha é obrigatório'})
  }

  if(password !== confirmpassword){
    res.status(422).send({msg : 'As senhas devem ser iguais!'})
  }

  // Verificando se usuário existe

  const userExist = await User.findOne({email : email})

  if(userExist){
    return res.status(422).send({msg : 'Usuário já cadastrado'})
  }

  // Create Password
  const salt = await bcrypt.genSalt(12)
  const passwordHash = await bcrypt.hash(password, salt)

  // Create User
  const user = new User({
    name,
    email,
    password: passwordHash
  })

  try{

    await user.save()

    res.status(201).json({msg : 'Usuário criado com sucesso'})

  } catch(error){
    res.status(400).json({msg : error})
  }
})


// Logar Usuário

app.post('/auth/user', async (req, res) => {

  const {email, password} = req.body

  //Validação

  if(!email || !password){
    res.status(422).send({msg : 'Preencha todos os campos'})
  }

  const user = await User.findOne({ email : email})

  if(!user){
    res.status(422).send({msg : 'Usuário não encontrado'})
  }

// Comparar Password

  const checkPassword = await bcrypt.compare(password, user.password)

  if(!checkPassword){
    return res.status(400).json({msg : 'Senha incorreta'})
  }

  try{
    const secret = process.env.SECRET
  
    const token = jwt.sign({
      id: user.id,
    }, secret)
  
    res.status(200).json({msg : 'Usuário logado com sucesso!', token})
  
  } catch (error) {
    res.status(500).json({ msg: error });
  }
})

// Credenciais

const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS

const url = `mongodb+srv://${dbUser}:${dbPassword}@apijwt.eqdpf84.mongodb.net/test`

mongoose
  .connect(url)
  .then(() => {
    app.listen(port, () => {
      console.log(`Servidor rodando => ${port}`);
    })
  })
  .catch(err => console.log(err));
