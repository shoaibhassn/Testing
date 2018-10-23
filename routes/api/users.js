const express = require("express");
const router = express.Router();
const gravatar = require("gravatar");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const keys = require("../../config/keys");

const passport = require("passport");
// load user model
const User = require("../../models/User");
//@route     GET api/users/test
// @desc     TEST post route
//@access    public
router.get("/test", (req, res) => res.json({ msg: "users works" }));
//@route     GET api/users/test
// @desc     Register user
//@access    public
router.post("/register", (req, res) => {
  User.findOne({ email: req.body.email }).then(user => {
    if (user) {
      return res.status(400).json({ email: "Email already exists" });
    } else {
      const avatar = gravatar.url(req.body.email, {
        s: "200", //Size
        r: "pg", //rating
        d: "mm" //default
      });

      const newUser = new User({
        name: req.body.name,
        email: req.body.email,
        avatar,
        password: req.body.password
      });
      bcrypt.genSalt(10, (err, salt) => {
        bcrypt.hash(newUser.password, salt, (err, hash) => {
          if (err) throw err;
          newUser.password = hash;

          newUser
            .save()
            .then(user => res.json(user))
            .catch(err => console.log(err));
        });
      });
    }
  });
});
//@route     GET api/users/login
// @desc     Login User /Returning JWT Token
//@access    public
router.post("/login", (req, res) => {
  const email = req.body.email;
  const password = req.body.password;
  //check for user
  User.findOne({ email }).then(user => {
    //Check for user
    if (!user) {
      return res.status(404).json({ email: "User not Found" });
    }
    //check password
    bcrypt.compare(password, user.password).then(isMatch => {
      if (isMatch) {
        //user Matched
        const payload = {
          id: user.id,
          name: user.name,
          avatar: user.avatar
        }; //Create JWT Payload

        //Sign token
        jwt.sign(
          payload,
          keys.secretOrkey,
          { expiresIn: "24h" },
          (err, token) => {
            res.json({
              success: true,
              token: "Bearer" + token //type of protocol
            });
          }
        );
      } else {
        return res.status(400).json({ password: "Password incorrect" });
      }
    });
  });
});
//@route     GET api/users/current
// @desc     Return current user
//@access    private
router.get(
  "/current",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    res.json({ msg: "success" });
  }
);
module.exports = router;
