# Building a Simple REST API with Node & Express

## Getting Started

```
npm init -y
nom i nodemon
npm i express dotenv
```

```js
// .gitignore

node_modules.env
```

```json
// package.json

"scripts": {
    "server": "nodemon server"
}
```

```js
// .env

NODE_ENV = development
PORT = 5000
```

## Basic Express Server

```js
// server.js

const express = require('express')
const dotenv = require('dotenv').config()
const port = process.env.PORT || 5000
const app = express()

app.listen(port, () => console.log(`Server started on port ${port}`))
```

## Sending Response

```js
// server.js

app.get('/api/goals', (res, req) => {
  res.send('Get goals')
})
app.get('/api/goals', (res, req) => {
  res.json({ message: 'Get goals' })
})
app.get('/api/goals', (res, req) => {
  res.status(200).json({ message: 'Get goals' })
})
```

## Routes

```js
// routes/goalRoutes.js

const express = require('express')
const router = express.Router()

router.get('/', (res, req) => {
  res.status(200).json({ message: 'Get goals' })
})
router.delete('/:id', (res, req) => {
  res.status(200).json({ message: `Delete goals ${req.params.id}` })
})
```

```js
// server.js

app.use('/api/goals', require('./routes/goalRoutes'))
```

## Controller

```js
// controllers/goalController.js

// @desc    Get goals
// @route   GET /api/goals
// @access  Public
const getGoals = (req, res) => {
  res.status(200).json({ message: 'Get goals' })
}

module.exports = { getGoals }
```

```js
// routes/goalRoutes.js

const { getGoals } = require('../controllers/goalController')

router.get('/', getGoals)
```

## Connecting Controller Functions

```js
// routes/goalRoutes.js

router.route('/').get(protect, getGoals).post(protect, setGoal)
router.route('/:id').delete(protect, deleteGoal).put(protect, updateGoal)
```

## Accepting Body Data

```js
// server.js

app.use(express.json())
app.use(express.urlencoded({ extended: false }))
```

```js
// controllers/goalController.js

const setGoals = (req, res) => {
  console.log(res.body)
}
```

## Error Handling

```js
// controllers/goalController.js

const setGoals = (req, res) => {
  if (!req.body.text)
    res.status(400).json({ message: 'Please add a text field' })
}

const setGoals = (req, res) => {
  if (!req.body.text) {
    res.status(400)
    throw new Error('Please add a text field')
  }
}
```

By default the express error handler will give a html page to change this add a middleware.

```js
// middleware/errorMiddleware.js

const errorHandler = (err, req, res, next) => {
  const statusCode = res.statusCode ? res.statusCode : 500

  res.status(statusCode)

  res.json({
    message: err.message,
    stack: process.env.NODE_ENV === 'production' ? null : err.stack,
  })
}

module.exports = {
  errorHandler,
}
```

```js
// server.js

const { errorHandler } = require('./middleware/errorMiddleware')

app.user(errorHandler)
```

## Async Handler

```

npm i express-async-handler
```

```js
// controllers/goalController.js

const asyncHandler = require('express-async-handler')

const getGoals = asyncHandler((req, res) => {
  res.status(200).json({ message: 'Get goals' })
})
```

## CORS

```
npm i cors
```

```js
const cors = require('cors')

app.use(
  cors({
    origin: '*',
    credentials: true,
  })
)
```

<br>

# Building a REST API With Node, Express and MongoDB

## Creating MongoDB Database

Login to mongoDB, create an organization, create a new project, add a user, connect your IP, create a database.<br>
Connect > connect your application > copy string

## Connect with Mongoose

```js
// .env

Mongo_URI = paste string and change user, password and database name
```

```js
// config/db.js

const mongoose = require('mongoose')

const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGO_URI)

    console.log(`MongoDB Connected: ${conn.connection.host}`)
  } catch (error) {
    console.log(error)
    process.exit(1)
  }
}

module.exports = connectDB
```

```js
// server.js

const connectDB = require('./config/db')

connectDB()
```

## Creating a Model

```js
// models/goalModel

const mongoose = require('mongoose')

const goalSchema = mongoose.Schema(
  {
    text: {
      type: String,
      required: [true, 'Please add a text value'],
    },
  },
  {
    timestamps: true,
  }
)

module.exports = mongoose.model('Goal', goalSchema)
```

**Type:** String, Number, Date, mongoose.SchemaTypes.ObjectId, [], [String], Object (like Addess: { street: Number, city: String}) <br>
**Validation:** required, lowercase, uppercase, default, immutable, min, max<br>
**Custom Validation:** validate: {validator: v => v % 2, message: props => `${props.value} is not a even number`}
**Note:** These validation will only work for create and save. For security only use findById and findOne and save. Or you can set the option "runValidators" to true.

## CRUD

### Create

```js
// controllers/goalControllers

const Goal = require('../models/goalModel')

const setGoal = asyncHandler(async (req, res) => {
  if (!req.body.text) {
    res.status(400)
    throw new Error('Please add a text field')
  }

  const goal = await Goal.create({
    text: req.body.text,
  })

  res.status(200).json(goal)
})
```

### Read

```js
const getGoals = asyncHandler(async (req, res) => {
  const goals = await Goal.find()

  res.status(200).json(goals)
})
```

### Update

```js
const updateGoal = asyncHandler(async (req, res) => {
  const goal = await Goal.findById(req.params.id)

  if (!goal) {
    res.status(400)
    throw new Error('Goal not found')
  }

  const updatedGoal = await Goal.findByIdAndUpdate(req.params.id, req.body, {
    new: true,
  })

  res.status(200).json(updatedGoal)
})
```

### Delete

```js
const deleteGoal = asyncHandler(async (req, res) => {
  const goal = await Goal.findById(req.params.id)

  if (!goal) {
    res.status(400)
    throw new Error('Goal not found')
  }

  await goal.remove()

  res.status(200).json({ id: req.params.id })
})
```

## Queries

```js
const user = await User.where('age')
  .gt('18')
  .lt('30')
  .where('name')
  .equals('John')
  .limit(2)
  .select('age')
const user = await User.where('age')
  .gt('18')
  .lt('30')
  .where('name')
  .equals('John')
  .limit(2)
  .populate('bestFriend')
```

<br>

# JWT Authentication

## Creating a Model

```js
// models/userModel.js

const mongoose = require('mongoose')

const userSchema = mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'Please add a name'],
    },
    email: {
      type: String,
      required: [true, 'Please add an email'],
      unique: true,
    },
    password: {
      type: String,
      required: [true, 'Please add a password'],
    },
  },
  {
    timestamps: true,
  }
)

module.exports = mongoose.model('User', userSchema)
```

## Protect Middleware

```js
// .env

JWT_SECRET = anyString
```

```js
// middleware/authMiddleWare.js

const jwt = require('jsonwebtoken')
const asyncHandler = require('express-async-handler')
const User = require('../models/userModel')

const protect = asyncHandler(async (req, res, next) => {
  let token

  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    try {
      // Get token from header
      token = req.headers.authorization.split(' ')[1]

      // Verify token
      const decoded = jwt.verify(token, process.env.JWT_SECRET)

      // Get user from the token
      req.user = await User.findById(decoded.id).select('-password')

      next()
    } catch (error) {
      console.log(error)
      res.status(403)
      throw new Error('Not authorized')
    }
  }

  if (!token) {
    res.status(401)
    throw new Error('Not authorized, no token')
  }
})

module.exports = { protect }
```

## Routes

```js
// routes/userRoutes.js

const express = require('express')
const router = express.Router()
const {
  registerUser,
  loginUser,
  getMe,
} = require('../controllers/userController')
const { protect } = require('../middleware/authMiddleware')

router.post('/', registerUser)
router.post('/login', loginUser)
router.get('/me', protect, getMe)

module.exports = router
```

## Controller

```js
// routes/userRoutes.js

const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
const asyncHandler = require('express-async-handler')
const User = require('../models/userModel')

// @desc    Register new user
// @route   POST /api/users
// @access  Public
const registerUser = asyncHandler(async (req, res) => {
  const { name, email, password } = req.body

  if (!name || !email || !password) {
    res.status(400)
    throw new Error('Please add all fields')
  }

  // Check if user exists
  const userExists = await User.findOne({ email })

  if (userExists) {
    res.status(400)
    throw new Error('User already exists')
  }

  // Hash password
  const salt = await bcrypt.genSalt(10)
  const hashedPassword = await bcrypt.hash(password, salt)

  // Create user
  const user = await User.create({
    name,
    email,
    password: hashedPassword,
  })

  if (user) {
    res.status(201).json({
      _id: user.id,
      name: user.name,
      email: user.email,
      token: generateToken(user._id),
    })
  } else {
    res.status(400)
    throw new Error('Invalid user data')
  }
})

// @desc    Authenticate a user
// @route   POST /api/users/login
// @access  Public
const loginUser = asyncHandler(async (req, res) => {
  const { email, password } = req.body

  // Check for user email
  const user = await User.findOne({ email })

  if (user && (await bcrypt.compare(password, user.password))) {
    res.json({
      _id: user.id,
      name: user.name,
      email: user.email,
      token: generateToken(user._id),
    })
  } else {
    res.status(400)
    throw new Error('Invalid credentials')
  }
})

// @desc    Get user data
// @route   GET /api/users/me
// @access  Private
const getMe = asyncHandler(async (req, res) => {
  res.status(200).json(req.user)
})

// Generate JWT
const generateToken = id => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: '30d',
  })
}

module.exports = {
  registerUser,
  loginUser,
  getMe,
}
```

## Making a Relation to User

```js
// models/goalRoutes.js

const mongoose = require('mongoose')

const goalSchema = mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      ref: 'User',
    },
    text: {
      type: String,
      required: [true, 'Please add a text value'],
    },
  },
  {
    timestamps: true,
  }
)

module.exports = mongoose.model('Goal', goalSchema)
```

```js
// controllers/goalController.js

// Create
const goal = await Goal.create({
  text: req.body.text,
  user: req.user.id,
})
// Read
const goals = await Goal.find({ user: req.user.id })
// Update & Delete
const goal = await Goal.findById(req.params.id)
if (goal.user.toString() !== req.user.id) {
  res.status(401)
  throw new Error('User not authorized')
}
```

<br>

# Advanced Authentication

##

```
npm i cookie-parser
```

```
require('crypto').randomBytes(64).toString('hex')
```

```js
// .env

ACCESS_TOKEN_SECRET = paste
REFRESH_TOKEN_SECRET = paste
```

```js
// controllers/userController.js

const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const nodemailer = require('nodemailer')
const asyncHandler = require('express-async-handler')
const User = require('../models/userModel')

// @desc    Signup a user
// @route   POST /auth/signup
// @access  Public
const signup = asyncHandler(async (req, res) => {
  const { name, email, password } = req.body
  // checking for fields
  if (!name) {
    res.status(400)
    throw new Error('Please add your name')
  }
  if (name.length < 5 || name.length > 21) {
    res.status(400)
    throw new Error('Name should be between 6 to 20 characters')
  }
  if (!email) {
    res.status(400)
    throw new Error('Please add your email')
  }
  if (!email.match(/^[\w-.]+@([\w-]+\.)+[\w-]{2,4}$/)) {
    res.status(400)
    throw new Error('Please add a valid email')
  }
  if (!password) {
    res.status(400)
    throw new Error('Please add your password')
  }
  if (
    !password.match(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[a-zA-Z]).{8,30}$/)
  ) {
    res.status(400)
    throw new Error('Password is too weak')
  }
  // checking if user already exists
  const userExists = await User.findOne({ email })
  if (userExists) {
    res.status(400)
    throw new Error('User already exists')
  }
  // hashing password
  const salt = await bcrypt.genSalt(10)
  const hashedPassword = await bcrypt.hash(password, salt)
  // creating the user in db
  const user = await User.create({
    name,
    email,
    password: hashedPassword,
    emailVerified: false,
    refreshToken: jwt.sign({ email }, process.env.REFRESH_TOKEN_SECRET, {
      expiresIn: '1d',
    }),
  })
  if (user) {
    // sending email confirmation
    const transporter = nodemailer.createTransport({
      host: 'smtp-mail.outlook.com',
      port: 587,
      auth: {
        user: 'mernauth@outlook.com',
        pass: process.env.EMAIL_PASS,
      },
    })
    await transporter.sendMail({
      from: 'mernauth@outlook.com',
      to: email,
      subject: 'Confirm your email',
      text: `Hello ${name}! Please confirm your email by clicking on this link https://authwithmern.herokuapp.com/verify/${jwt.sign(
        { email },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: '15min' }
      )}`,
    })
    // sending response
    res.status(201).json({
      message: 'Email Sent',
    })
  } else {
    res.status(400)
    throw new Error('Invalid user data')
  }
})

// @desc    Resent verification email
// @route   POST /auth/resent
// @access  Public
const resent = asyncHandler(async (req, res) => {
  const { email } = req.body
  // checking fields
  if (!email) {
    res.status(400)
    throw new Error('Please add your email')
  }
  // checking if user exists
  const user = await User.findOne({ email })
  if (!user) {
    res.status(400)
    throw new Error("User doesn't Exist")
  }
  // sending email confirmation
  const transporter = nodemailer.createTransport({
    host: 'smtp-mail.outlook.com',
    port: 587,
    auth: {
      user: 'mernauth@outlook.com',
      pass: process.env.EMAIL_PASS,
    },
  })
  await transporter.sendMail({
    from: 'mernauth@outlook.com',
    to: email,
    subject: 'Confirm your email',
    text: `Hello ${
      user.name
    }! Please confirm your email by clicking on this link https://authwithmern.herokuapp.com/verify/${jwt.sign(
      { email },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: '15min' }
    )}`,
  })
  // sending response
  res.status(201).json({
    message: 'Email Sent',
  })
})

// @desc    Verify user email
// @route   POST /auth/verify
// @access  Public
const verify = asyncHandler(async (req, res) => {
  const { token } = req.body
  if (!token) {
    res.status(401)
    throw new Error('Not authorized, no token')
  }
  try {
    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET)
    const user = await User.findOne({ email: decoded.email })
    user.emailVerified = true
    user.save()
    res.status(200).json({
      message: 'Email Verified',
    })
  } catch (err) {
    res.status(403)
    throw new Error('Not authorized')
  }
})

// @desc    Authenticate a user
// @route   POST /auth/login
// @access  Public
const login = asyncHandler(async (req, res) => {
  const { email, password } = req.body
  // check for fields
  if (!email) {
    res.status(400)
    throw new Error('Please add your email')
  }
  if (!password) {
    res.status(400)
    throw new Error('Please add your password')
  }
  // checking if user exists
  const user = await User.findOne({ email })
  // checking credentials
  if (user && (await bcrypt.compare(password, user.password))) {
    // checking if email is verified
    if (!user.emailVerified) {
      res.status(400)
      throw new Error('Email not verified')
    }
    // saving refresh token and sending it
    const refreshToken = jwt.sign({ email }, process.env.REFRESH_TOKEN_SECRET, {
      expiresIn: '1d',
    })
    user.refreshToken = refreshToken
    user.save()
    // sending response
    res.cookie('jwt', refreshToken, {
      httpOnly: true,
      sameSite: 'None',
      secure: true,
      maxAge: 24 * 60 * 60 * 1000,
    })
    res.json({
      _id: user.id,
      name: user.name,
      email: user.email,
      accessToken: jwt.sign({ email }, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: '15min',
      }),
    })
  } else {
    res.status(400)
    throw new Error('Invalid credentials')
  }
})

// @desc    Refresh access token
// @route   POST /auth/refresh
// @access  Public
const refresh = asyncHandler(async (req, res) => {
  // checking for cookies
  const cookies = req.cookies
  if (!cookies?.jwt) return res.sendStatus(401)
  const refreshToken = cookies.jwt

  // finding user
  const user = await User.findOne({ refreshToken })
  // if no user
  if (!user) {
    res.sendStatus(403)
  }
  const accessToken = jwt.sign(
    { email: user.email },
    process.env.ACCESS_TOKEN_SECRET
  )
  res.status(200).json({ accessToken })
})

// @desc    Logout a user
// @route   POST /auth/logout
// @access  Private
const logout = asyncHandler(async (req, res) => {
  const cookies = req.cookies
  // checking for cookie
  if (!cookies?.jwt) return res.sendStatus(204)
  // retriving cookie
  const refreshToken = cookies.jwt
  // checking for cookie in db
  const user = await User.findOne({ refreshToken })
  // if not clear cookie
  if (!user) {
    res.clearCookie('jwt', { httpOnly: true, sameSite: 'None', secure: true })
    return res.sendStatus(204)
  }
  // if yes clear cookie and delete from db
  user.refreshToken = ''
  user.save()
  res.clearCookie('jwt', { httpOnly: true, sameSite: 'None', secure: true })
  res.sendStatus(204)
})

// @desc    Change User Password
// @route   POST /auth/changepassword
// @access  Private
const changePassword = asyncHandler(async (req, res) => {
  const { currentPassword, newPassword } = req.body
  // checking fields
  if (!currentPassword) {
    res.status(400)
    throw new Error('Please enter your current password')
  }
  if (!newPassword) {
    res.status(400)
    throw new Error('Please enter your new password')
  }
  // checking current password
  const user = await User.findOne({ email: req.user.email })
  if (await bcrypt.compare(currentPassword, user.password)) {
    // changing password
    const salt = await bcrypt.genSalt(10)
    const hashedPassword = await bcrypt.hash(newPassword, salt)
    user.password = hashedPassword
    user.save()
    res.status(200).json({ message: 'Password change' })
  } else {
    res.status(403)
    throw new Error('Current password is invalid')
  }
})

// @desc    Reset User Password
// @route   POST /auth/resetpassword
// @access  Public
const resetPasswordLink = asyncHandler(async (req, res) => {
  const { email } = req.body
  // checking fields
  if (!email) {
    res.status(400)
    throw new Error('Please enter your email')
  }
  // finding the user
  const user = await User.findOne({ email })
  if (!user) {
    // if no user send message only
    res.status(200).json({ message: 'Password reset link send' })
  }
  // sending password reset
  const transporter = nodemailer.createTransport({
    host: 'smtp-mail.outlook.com',
    port: 587,
    auth: {
      user: 'mernauth@outlook.com',
      pass: process.env.EMAIL_PASS,
    },
  })
  await transporter.sendMail({
    from: 'mernauth@outlook.com',
    to: email,
    subject: 'Reset Password Link',
    text: `Hello ${
      user.name
    }! Please reset your password by clicking on this link https://authwithmern.herokuapp.com/resetpassword/${jwt.sign(
      { email },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: '15min' }
    )}`,
  })
  res.status(200).json({ message: 'Password reset link send' })
})

// @desc    Reset User Password
// @route   POST /auth/resetpassword
// @access  Public
const resetPassword = asyncHandler(async (req, res) => {
  const { token, password } = req.body
  // checking fields
  if (!token) {
    res.status(401)
    throw new Error('Not authorized, no token')
  }
  if (!password) {
    res.status(400)
    throw new Error('Please add your new password')
  }
  try {
    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET)
    const user = await User.findOne({ email: decoded.email })
    const salt = await bcrypt.genSalt(10)
    const hashedPassword = await bcrypt.hash(password, salt)
    user.password = hashedPassword
    user.save()
    res.status(200).json({
      message: 'Password Changed',
    })
  } catch (err) {
    res.status(403)
    throw new Error('Not authorized')
  }
})

// @desc    Get current user
// @route   GET /auth/user
// @access  Private
const user = asyncHandler(async (req, res) => {
  res.status(200).json({ user: req.user })
})

module.exports = {
  signup,
  resent,
  verify,
  login,
  refresh,
  logout,
  changePassword,
  resetPasswordLink,
  resetPassword,
  user,
}
```

## User Roles - Authorization

```js
// config/roles_list.js

const ROLES_LIST = {
  Admin: 5150,
  Editor: 1984,
  User: 2001,
}

module.exports = ROLES_LIST
```

```js
// controller/userController.js

const user = await User.create({
  name,
  email,
  password: hashedPassword,
  refreshToken: generateRefreshToken(user._id),
  roles: { User: 2001 },
})
```

```js
// in generating the accessToken
const generateAccessToken = id => {
  jwt.sign({ id, roles }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '5m' })
}
// no need to send the roles in generate refresh token
const accessToken = jwt.sign(
      { foundUser.user_.id, foundUser.roles },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: '5m' }
    )
// in protect
req.roles = decoded.roles
```

```js
// middleware.verifyRoles.js

const verifyRoles = (...allowedRoles) => {
  return (req, res, next) => {
    if (!req?.roles) return res.sendStatus(401)
    const rolesArray = [...allowedRoles]
    const result = req.roles
      .map(role => rolesArray.includes(role))
      .find(val => val === true)
    if (!result) return res.sendStatus(401)
    next()
  }
}

module.exports = verifyRoles
```

```js
/// controllers/userController.js

routers.router('/').post(verifyRoles[ROLES_LIST.admin], setGoal)
```

<br>

# Sending Email

```js
const nodemailer = require('nodemailer')

let transporter = nodemailer.createTransport({
  host: 'smtp.ethereal.email',
  port: 587,
  secure: false, // true for 465, false for other ports
  auth: {
    user: testAccount.user, // generated ethereal user
    pass: testAccount.pass, // generated ethereal password
  },
  tls: {
    rejectUnauthorized: false, // from localhost
  },
})

// send mail with defined transport object
let info = await transporter.sendMail({
  from: '"Fred Foo 👻" <foo@example.com>', // sender address
  to: 'bar@example.com, baz@example.com', // list of receivers
  subject: 'Hello ✔', // Subject line
  text: 'Hello world?', // plain text body
  html: '<b>Hello world?</b>', // html body
})
```

<br>

# Pagination

```js
// middleware/paginatedResults.js

const paginatedResults = model => {
  return async (req, res, next) => {
    const page = parseInt(req.query.page)
    const limit = parseInt(req.query.limit)

    const startIndex = (page - 1) * limit
    const endIndex = page * limit

    const results = {}

    if (endIndex < (await model.countDocuments().exec())) {
      results.next = {
        page: page + 1,
        limit: limit,
      }
    }

    if (startIndex > 0) {
      results.previous = {
        page: page - 1,
        limit: limit,
      }
    }
    try {
      results.results = await model.find().limit(limit).skip(startIndex).exec()
      res.paginatedResults = results
      next()
    } catch (e) {
      res.status(500).json({ message: e.message })
    }
  }
}
```

```js
// routes

app.get('/users', paginatedResults(User), (req, res) => {
  res.json(res.paginatedResults)
})
```

```js
// request

'GET http://localhost:5000/users?page=1&limit=14'
```

<br>

# File Upload

```js
import multer from 'multer'

const storage = multer.diskStorage({
  destination(req, file, cb) {
    cb(null, 'uploads/')
  },
  filename(req, file, cb) {
    cb(
      null,
      `${file.fieldname}-${Date.now()}${path.extname(file.originalname)}`
    )
  },
})

function checkFileType(file, cb) {
  const filetypes = /jpg|jpeg|png/
  const extname = filetypes.test(path.extname(file.originalname).toLowerCase())
  const mimetype = filetypes.test(file.mimetype)

  if (extname && mimetype) {
    return cb(null, true)
  } else {
    cb('Images only!')
  }
}

const upload = multer({
  storage,
  limits: { fileSize: 1000000 },
  fileFilter: function (req, file, cb) {
    checkFileType(file, cb)
  },
})

router.post('/', upload.single('image'), (req, res) => {
  res.send(`/${req.file.path}`)
})

router.post('/multiple', upload.array('image', 3), (req, res) => {
  res.send(`/${req.file.path}`)
})

export default router
```

```js
// deleting files

const fs = require('fs')

const deleteFile = filePath => {
  fs.unlink(filePath, err => {
    throw err
  })
}
deleteFile(product.imageUrl)
```
