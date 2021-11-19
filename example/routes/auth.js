var express = require("express");
var passport = require("passport");
var router = express.Router();

router.post(
  "/callback/google-one-tap",
  passport.authenticate("google-one-tap", { failureRedirect: "/" }),
  function (req, res, next) {
    res.redirect("/");
  }
);

router.get("/logout", function (req, res, next) {
  req.logout();
  res.redirect("/");
});

module.exports = router;
