const express = require('express');
const app = express();
const bcrypt = require('bcrypt-nodejs');
const cors = require('cors');
const knex = require('knex');
const register = require('./controllers/register')
const signin = require('./controllers/signin')
const profile = require('./controllers/profile')
const image = require('./controllers/image')
const morgan = require('morgan');

//For Heroku
process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0; 
const db = knex({
  client: 'pg',
  connection: {
    connectionString: process.env.DATABASE_URL,
     ssl: {
    rejectUnauthorized: false
    }
  }
});

//For Local
// const db = knex({
//   client: 'pg',
//   connection: {
//     host : '127.0.0.1',
//     port : 5432,
//     user : 'postgres',
//     password : 'test',
//     database : 'smart-brain'
//   }
// });

app.use(express.json());
// app.use(morgan('combined'));

// app.use(cors());

app.get('/', (req, res) => { res.send('success');});

app.post('/signin', (req, res) => { signin.handleSignin(req, res, db, bcrypt) });

app.post('/register', (req, res) => {register.handleRegister(req, res, db, bcrypt)});

app.get('/profile/:id', (req, res) => { profile.handleProfileGet(req, res, db)});

app.put('/image', (req, res) => { image.handleImage(req, res, db)});

app.post('/imageurl', (req, res) => { image.handleApiCall(req, res)});

// app.listen(3001, () => { console.log('Server is running on port: 3001');});
app.listen(process.env.PORT || 3001, () => { console.log(`Server is running on port: ${process.env.PORT}`);});
