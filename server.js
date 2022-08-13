const express = require('express');
const app = express();
const bcrypt = require('bcrypt-nodejs');
const cors = require('cors');
const knex = require('knex');

const db = knex({
  client: 'pg',
  connection: {
    host : '127.0.0.1',
    port : 5432,
    user : 'postgres',
    password : 'test',
    database : 'smart-brain'
  }
});



// app.use(express.urlencoded({extended: false}));
app.use(express.json());
app.use(cors());

const database = {
	users: [ 
		{
			id: '123',
			name: 'john',
			email: 'john@gmail.com',
			password: 'cookies',
			entries: 0,
			joined: new Date()
		},
		{
			id: '124',
			name: 'sally',
			email: 'sally@gmail.com',
			password: 'bananas',
			entries: 0,
			joined: new Date()
		},
	],
	login: [
		{
			id: '987',
			hash: '',
			email: 'john@gmail.com'
		}


	]
}


app.get('/', (req, res) => {
	res.send('success');
});


app.post('/signin', (req, res) => {
	db.select('email', 'hash').from('login')
	.where('email', '=', req.body.email)
	.then(data => {
		const isValid = bcrypt.compareSync(req.body.password, data[0].hash);
		if (isValid){
			return db.select('*').from('users')
			.where('email', '=', req.body.email)
			.then(user => {
				res.json(user[0]);
			})
			.catch(err => res.status(400).json('unable to get user'));
		}
		else{
			res.status(400).json('wrong credentials');
		}
	})
	.catch(err => res.status(400).json('wrong credentials'))
});

app.post('/register', (req, res) => {
	const { email, name, password } = req.body;

	const hash = bcrypt.hashSync(password);

	db.transaction(trx => {
		trx.insert({
			hash: hash,
			email: email})
		.into('login')
		.returning('email')
		.then(loginEmail => {
			return trx('users')
				.returning('*')
				.insert({
					email: loginEmail[0].email,
					name: name,
					joined: new Date()
				}).
				then(user => {
					res.json(user[0])
					});
				}
			)
		.then(trx.commit)
		.catch(trx.rollback);
		}
	)
			
	.catch(err => res.status(400).json('Unable to register'));
});

app.get('/profile/:id', (req, res) => {
	const { id } = req.params;
	db.select('*').from('users')
	.where({id})
	.then(user => {
		if (user.length) {
			res.json(user[0]);
		}
		else{
			res.status(400).json('User not found')
		}

	})
	.catch(err => res.status(400).json('Error getting user'));
});

app.put('/image', (req, res) => {
	const { id } = req.body;
	db('users').where('id', '=', id)
	.increment('entries', 1)
	.returning('entries')
	.then(entries => {
		res.json(entries[0]);
	})
	.catch(err => res.status(400).json('unable to get entries'));
})



// // Load hash from your password DB.
// bcrypt.compare("bacon", hash, function(err, res) {
//     // res == true
// });
// bcrypt.compare("veggies", hash, function(err, res) {
//     // res = false
// });

// bcrypt.hash(password, null, null, function(err, hash) {
// 	console.log(hash);
// });

app.listen(3001, () => {
	console.log('Server is running on port: 3001');
});
