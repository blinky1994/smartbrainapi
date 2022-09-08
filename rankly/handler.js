'use strict';

const symbols = ['♟','♜', '♞', '♝', '♚', '♛'];

module.exports.rank = async (event) => {
  const rank = event.queryStringParameters.rank;
  const rankSymbol = symbols[rank >= symbols.length ? symbols.length-1 : rank];

  return {
    statusCode: 200,
    headers: {
      'Access-Control-Allow-Origin': '*'
    },
    body: JSON.stringify(
      {
        message: 'Go Serverless v1.0! Your function executed successfully!',
        input: rankSymbol,
      },
      null,
      2
    ),
  };

  // Use this code if you don't use the http event with the LAMBDA-PROXY integration
  // return { message: 'Go Serverless v1.0! Your function executed successfully!', event };
};
