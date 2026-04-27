import express = require('express')
import ApiStatusCodes from '../../api/ApiStatusCodes'
import BaseApi from '../../api/BaseApi'
import CaptainConstants from '../../utils/CaptainConstants'

const router = express.Router()

// Clears the auth cookie set by /login. The bearer token in the response body
// cannot be revoked individually (only by rotating the server-wide
// tokenVersion via password change), so this endpoint only handles the
// browser-side cookie. Clients should drop their stored token alongside
// calling this.
router.post('/', function (req, res, next) {
    res.clearCookie(CaptainConstants.headerCookieAuth, { path: '/' })
    res.send(new BaseApi(ApiStatusCodes.STATUS_OK, 'Logout succeeded'))
})

export default router
