
const bcrypt = require('bcryptjs');
const express = require('express');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const secrets = require('./secrets.js');

const server = express();
server.use(helmet());
server.use(express.json());

// const restrictedRouter = require('./restricted-router.js');
// server.use('/api/restricted', tokenCheck, restrictedRouter);

const db = require('./data/dbConfig.js');

server.get('/api/users', tokenCheck, async (req,res) => {
    try {
        const result = await db('users');
        res.status(200).json(result);
    }
    catch(err) {
        res.status(500).json({err});
    }
});

server.post('/api/register', async (req,res) => {
    let user = req.body;
    if (!user.username || !user.password) {
        res.status(400).json({error:'please provide username/password'});
    } else {
        user.password = bcrypt.hashSync(user.password, 8);
        try {
            const result = await db('users').insert(user);
            if (result) {
                const newUser = await db('users').where({'id':result[0]}).first();
                res.status(201).json(newUser);
            }
        }
        catch(err) {
            res.status(500).json(err);
        }
    }
});

server.post('/api/login', async (req,res) => {
    let {username,password} = req.body;
    if (!username || !password) {
        res.status(400).json({error:'please provide username/password'});
    } else {
        try {
            const validUser = await db('users').where({username}).first();
            if (validUser && bcrypt.compareSync(password, validUser.password)) {
                const token = generateToken(user);
                res.status(200).json({message: `${validUser.username} LOGGED IN`,token});
            } else {
                res.status(401).json({message:'invalid credentials'});
            }
        }
        catch(err) {
            res.status(500).json(err);
        }
    }
});

server.get('/api/logout', async (req,res) => {
    try {
        if (req.session) {
            req.session.destroy(err => {
              if (err) {
                res.status(500).json(err);
              } else {
                res.status(200).json({message: 'logged out'});
              }
            });
          } else {
            res.status(500).json({error: 'no session found'});
          }
    }
    catch (err) {
        res.status(500).json(err);
    }
});

function tokenCheck(req,res,next) {
    const token = req.headers.authorization;
    if (token) {
      jwt.verify(token, secrets.jwtSecret, (error, decodedToken) => {
        if (error) {
          res.status(401).json({message:'invalid credentials'});
        } else {
          req.decodedJwt = decodedToken;
          next();
        }
      });
    } else {
      res.status(401).json({message:'no token provided'});
    }
}

function generateToken(user) {
    const payload = {
      subject: user.id,
      username: user.username,
      roles: ['student','ta'],
    };
    const options = {
      expiresIn: '1d',
    };
    return jwt.sign(payload, secrets.jwtSecret, options);
  }

module.exports = server;
