const { response } = require("express");

const handleProfileGet = (req, res, db) => {
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
}

const handleProfileUpdate = (req, res, db) => {
	const { id } = req.params;
	const { name, age, pet } = req.body.formInput;

	db.select('*').from('users')
	.where({id})
	.update({name})
	.then(resp => {
		if (resp)
		{
			res.json('success');
		} else {
			res.status(400).json('Unable to update')
		}
	})
	.catch(err => res.json(err));
}

module.exports = {
    handleProfileGet,
	handleProfileUpdate
}