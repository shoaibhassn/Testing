const express = require("express");
const router = express.Router();
//@route     GET api/post/test
// @desc     TEST post route
//@access    public
router.get("/test", (req, res) => res.json({ msg: "posts works" }));
module.exports = router;
