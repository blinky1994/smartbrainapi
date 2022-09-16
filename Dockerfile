FROM node:16.16.0

# add `/app/node_modules/.bin` to $PATH
ENV PATH /app/node_modules/.bin:$PATH

# install app dependencies
COPY ./package*.json ./
RUN npm install

# add app
COPY ./ ./

# start app
CMD ["npm", "start"]