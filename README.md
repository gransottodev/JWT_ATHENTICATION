# JWT AUTHENTICATION

API de Autenticação utilizando NODEJS

## 🚀 Começando

Essas instruções permitirão que você obtenha uma cópia do projeto em operação na sua máquina local.

Clone este repositório:
```
git clone https://github.com/gransottodev/JWT_ATHENTICATION.git
```

### 📋 Pré-requisitos

O que você precisa para instalar o software?

```
Node.js Versão 16.15.1 (Que no momento é a versão LTS)
```

### 🔧 Instalação

npm install
```
Após a instalação você ele deve ter baixado uma pasta chamada node_modules e um arquivo chamado package.json onde você poderá ver as dependências do projeto já instaladas, conforme abaixo:  
 


## Rodando a aplicação:

Para rodas a aplicação basta utilizar o seguinte comando no terminal:
node app.js
```

```
## End-Points da API

Register
http://localhost:3000/auth/register

Login
http://localhost:3000/auth/user

GetById (PRIVATE ROUTE)
Para acessar essa rota insira o Token obtido no End-Point Anterior no Header da requisição!
http://localhost:3000/user/:id     

```

---

## 🛠️ Construído com as seguintes ferramentas:

* [Json Web Token](https://jwt.io)
* [Bcrypt](https://www.npmjs.com/package/bcrypt)
* [Node](https://nodejs.org/en/docs/)
* [Mongoose](https://mongoosejs.com)


---
