const express = require('express')
const auth = require('../../middleware/auth')
const router = express.Router();
const User = require('../../models/User')
const { body, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken')
const config = require('config')
const bcrypt = require('bcryptjs');

//@route    GET api/auth
// desc         Test route
// @access Public
router.get('/', auth, async(req, res) => {
    try{
        const user = await User.findById(req.user.id).select('-password')
        res.json(user);
    }catch(err){
        console.error(err.message);
        res.status(500).send('Server Error')
    }
});

//@route    POST api/auth
// desc         Authneticate User and get token
// @access Public
router.post('/',[
    body('email', 'Please include a valid Email').isEmail(),
    body('password', 'Password is required').exists(),
] ,async(req, res) => {
    const errors = validationResult(req);

    if(!errors.isEmpty()){
        return res.status(400).json({errors: errors.array()})
    }
    const { email, password} = req.body

    try{
        
    //See if users exist
        let user = await User.findOne({email});

        if(!user){
            res.status(400).json({errors: [{msg: 'Invalid Credentials'}]});
        };

    // See if password matches
        const isMatch = await bcrypt.compare(password, user.password)

        if(!isMatch){
            res.status(400).json({errors: [{msg: 'Invalid Credentials'}]});
        }

    //Return jsonwebtoken
        const payload = {
            user: {
                id: user.id
            }
        }

        jwt.sign(payload, config.get('jwtSecret'), {expiresIn: 3600000}, (err, token) => {
            if(err) throw err;
            res.json({token})
        })

    }catch(err){
        console.error(err.message);
        res.status(500).send('Server error')
    }

    }
)


module.exports = router;