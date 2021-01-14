const bcrypt = require('bcryptjs')

module.exports = {
    register: async(req, res) => {
        //What does this function need to work properly?
        const {email, password} = req.body
        const db = req.app.get('db')

        //Check if the user already has an account with the check_user query
        const foundUser = await db.check_user({email})
        if(foundUser[0]){
            return res.status(400).send('Email already in use')
        }

        //Hash and salt the users password, insert their info into the db genSaltSync(#ofCharacters)
        let salt = bcrypt.genSaltSync(10)
        const hash = bcrypt.hashSync(password, salt)
        
        const newUser = await db.register_user({email, hash})

        //Place the user on a session, and send their info client-side
        req.session.user = newUser[0]
        res.status(201).send(req.session.user)
    },
    login: async(req, res) => {
        //What does this function need to work properly?
        const {email, password} = req.body 
        const db = req.app.get('db')
        // console.log('hit', req.body)

        //Check to see if the email is in the db
        const foundUser = await db.check_user({email})
        if(!foundUser[0]){
            return res.status(404).send('Email not found')
        }

        //Make sure the password patches the hash value
        const authenticated = bcrypt.compareSync(password, foundUser[0].password)
        if(!authenticated){
            return res.status(401).send('Password is incorrect')
        }
                     //delete client side password
        delete foundUser[0].password

        //Place the user ona  session, and send the info client-side
        req.session.user = foundUser[0]
        res.status(202).send(req.session.user)
    },
    logout: (req, res) => {
        //Clear the user session
        req.session.destroy()
        //Send back a status code
        res.sendStatus(200)
    }
}