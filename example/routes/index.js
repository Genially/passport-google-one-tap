var express = require("express");
var router = express.Router();

/* GET home page. */
router.get("/", function (req, res, next) {
  res.render("index", {
    title: "Passport Google One Tap Example",
    googleClientId: process.env["GOOGLE_CLIENT_ID"],
    user: req.user,
  });
});

module.exports = router;
