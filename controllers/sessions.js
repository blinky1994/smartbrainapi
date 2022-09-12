const jwt = require('jsonwebtoken');
const redis = require('redis');

//Set up redis
const redisClient = redis.createClient(process.env.REDIS_URI);

const getAuthTokenID = (req, res) => {
	const { authorization } = req.headers;
	return redisClient.get(authorization, (err, reply) => {
		if (err || !reply) {
			return res.status(400).json('Unauthorized');
		}
		return res.json({id: reply} );
	});
}

const signToken = (email) => {
	const jwtPayload = { email };
	return jwt.sign(jwtPayload, 'JET_Secret', { expiresIn: '2 days'});
}

const setToken = (key, value) => {
	return Promise.resolve(redisClient.set(key, value));
}

const createSessions = (user) => {
	//JWT token, return user data
	const { email, id } = user;
	const token = signToken(email);
	return setToken(token, id)
	.then(() => ({ success: 'true', userID: id, token }))
	.catch(console.log);
} 

module.exports = {
    getAuthTokenID,
    signToken,
    setToken,
    createSessions,
	redisClient
}