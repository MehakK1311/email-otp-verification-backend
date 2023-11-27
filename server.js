const app = require('express')();
const UserRouter = require('./api/User.js')
require('./config/db.js')
const PORT = 3000;

const bodyParser = require('express').json;
app.use(bodyParser());

app.use('/user', UserRouter);

app.listen(PORT, ()=>{
    console.log(`listening on port ${PORT}`);
})