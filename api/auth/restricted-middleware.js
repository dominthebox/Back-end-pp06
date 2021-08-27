const jwt = require('jsonwebtoken')
const { TOKEN_SECRET } = require('../../config/secrets')



module.exports = (req, res, next) => {
  // the server expects to find the token in Authorization
  const token = req.headers.authorization

  if (token) {
    // async function
    jwt.verify(token, TOKEN_SECRET, (err, decoded) => {
      if (err) {
        next({ status: 401, message: `token bad: ${err.message}` })
      } else {
        req.decodedJwt = decoded
        next()
      }
    }) // old style node async callback
  } else {
    next({ status: 401, message: 'we wants token!' })
  }
};