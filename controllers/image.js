const Clarifai = require('clarifai');
require('dotenv').config();

const app = new Clarifai.App({
 apiKey: '15213ace8fe2459eba5522c4b00f5eae'
});


const handleApiCall = (req, res) => {
	app.models
	.predict(Clarifai.FACE_DETECT_MODEL, req.body.input)
	.then(data => { res.json(data); })
	.catch(err => res.status(400).json('unable work with API'))
}


const handleImage = (req, res, db) => {
	const { id } = req.body;
	db('users').where('id', '=', id)
	.increment('entries', 1)
	.returning('entries')
	.then(entries => {
		res.json(entries[0]);
	})
	.catch(err => res.status(400).json('unable to get entries'));
}

module.exports = {
	handleImage,
	handleApiCall
}