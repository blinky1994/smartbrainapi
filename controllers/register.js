const sessions = require('./sessions');

const handleRegister = (db, bcrypt, req, res) => {
	const { email, password, name } = req.body;
	if (!email || !name || !password) {
		return Promise.reject('Incorrect form submission');
	}
	const hash = bcrypt.hashSync(password);

	return db.transaction(trx => {
		trx.insert({
			hash: hash,
			email: email})
		.into('login')
		.returning('email')
		.then(
			loginEmail => {
			return trx('users')
				.returning('*')
				.insert({
					email: loginEmail[0].email,
					name: name,
					joined: new Date()
				})
				.then(user => user[0]);
				}
			)
		.then(trx.commit)
		.catch(trx.rollback);
		}
	)
	.catch(err => Promise.reject(400).json(err));
}

const registerAuthentication = (db, bcrypt) => (req, res) => {
	return handleRegister(db, bcrypt, req, res)
		.then(data => {
			return data.id && data.email ? sessions.createSessions(data) : Promise.reject(data);
		})
		.then(session => {res.json(session)})
		.catch(err => res.status(400).json(err));
}

module.exports = {
    registerAuthentication,
}