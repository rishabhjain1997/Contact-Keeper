const express = require('express')
const router = express.Router()
const {check, validationResult} = require('express-validator/check')
const User = require('../models/User')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const config = require('config')
const auth = require('../middleware/auth')


// @route POST api/auth
// @desc Log in user
// @access Public

router.post('/',[
    check('email', 'Please include a valid email').isEmail(),
    check('password', 'Please include a valid password').exists()
],
async (req,res) => {
    const errors = validationResult(req)
    if(!errors.isEmpty())
    {
        return res.status(400).json({errors: errors.array()})
    }

    const {email, password} = req.body
    try {
        let user = await User.findOne({email})
        if(!user)
        {
            res.status(400).json({msg: 'Invalid credentials'})
        }
        const isMatch = await bcrypt.compare(password, user.password)
        if(!isMatch)
        {
            res.status(400).json({msg: 'Invalid credentials'})
        }
               const payload = {
           user:
           {
               id: user.id
           }
       }

       jwt.sign(payload, config.get('jwtSecret'), {
           expiresIn: 3600
       },
       (err, token) => {
           if (err)
           {
               throw err
           }
           res.json({token})
       })

    } catch (error) {
        console.error(err.message)
        res.status(500).send('Server Error')
    }
    
})


// @route GET api/auth
// @desc Get Log in user
// @access Private

router.get('/',auth, async(req,res) => {
    try {
        const user = await User.findById(req.user.id).select('-password')
        res.json(user)
    } catch (err) {
        console.error(err.message)
        res.status(500).send('Server Error')
    }
})


module.exports = router
