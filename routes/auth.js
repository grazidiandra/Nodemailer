const express = require("express");
const passport = require('passport');
const router = express.Router();
const nodemailer = require('nodemailer');
const User = require("../models/User");
const multer  = require('multer');

// Bcrypt to encrypt passwords
const bcrypt = require("bcrypt");
const bcryptSalt = 10;

//multer
const upload = multer({ dest: './public/uploads/' });


router.get("/login", (req, res, next) => {
  res.render("auth/login", { "message": req.flash("error") });
});

router.post("/login", passport.authenticate("local", {
  successRedirect: "/auth/profile",
  failureRedirect: "/auth/login",
  failureFlash: true,
  passReqToCallback: true
}));

router.get("/signup", (req, res, next) => {
  res.render("auth/signup");
});

router.post("/signup", upload.single('photo'), (req, res, next) => {
  const username = req.body.username;
  const password = req.body.password;
  const email = req.body.email;
  const path= `/uploads/${req.file.filename}`;
  const originalName = req.file.originalname;
  
  console.log(path)
  if (username === "" || password === "") {
    res.render("auth/signup", { message: "Indicate username and password" });
    return;
  }

  User.findOne({ username }, "username", (err, user) => {
    if (user !== null) {
      res.render("auth/signup", { message: "The username already exists" });
      return;
    }

    const salt = bcrypt.genSaltSync(bcryptSalt);
    const hashPass = bcrypt.hashSync(password, salt);

    //Token generation:
    const characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    let token = '';
    for (let i = 0; i < 25; i++) {
      token += characters[Math.floor(Math.random() * characters.length)];
    }

    const newUser = new User({
      username,
      password: hashPass,
      email,
      confirmationCode: token,
      path,
      originalName
    });

    newUser.save()
    .then(() => {
      let transporter = nodemailer.createTransport({
        service: 'Gmail',
        auth: {
          user: process.env.EMAIL,
          pass: process.env.EMAIL_PASS
        }
      });
      transporter.sendMail({
        from: '"Nodemailer Test App " <ironhack.test.no.reply@gmail.com>',
        to: newUser.email, 
        subject: "Your confirmation code", 
        text: `
              Hi, ${newUser.name}
              To complete your registration, please follow this link:
              http://localhost:3000/auth/confirm/${newUser.confirmationCode}
              `,
        html: `
             <div>
              <h2 style="color:red;text-align:center;">Hi, <b>${newUser.username}</b></h2>
              <p style="color:green;text-align:center;">To complete your registration, please follow this link: </p>
              <p style="color:yellow;text-align:center;">http://localhost:3000/auth/confirm/${newUser.confirmationCode}</p>
              </div>
              `
      })
      .then(() => res.redirect("/"))
      .catch(err => {
        res.render("auth/signup", { message: `Something went wrong ${err}` });
      });
    });
  });
});

router.get("/logout", (req, res) => {
  req.logout();
  res.redirect("/");
});

router.get('/confirm/:confirmCode', (req, res, next) => {
  const { confirmCode } = req.params
  User.findOneAndUpdate({ confirmationCode: confirmCode }, { $set: {status: 'Active' }}, { new:true })
  .then(updatedUser => res.render('auth/confirmation', {updatedUser}))
  .catch(err => res.render('auth/confirmation', {err}))
});

router.get('/profile', (req, res) =>{
  res.render('auth/profile', req.user)
})

module.exports = router;
