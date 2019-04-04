
require('dotenv').config();
const server = require('./server.js');

server.get('/', (req, res) => {
    res.send('no place in the world');
});

const port = process.env.PORT || 5000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));
