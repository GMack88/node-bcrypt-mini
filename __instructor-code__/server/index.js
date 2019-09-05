require("dotenv").config();
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const massive = require("massive");

const app = express();

app.use(express.json());

let { SERVER_PORT, CONNECTION_STRING, SESSION_SECRET } = process.env;

app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false
  })
);

massive(CONNECTION_STRING).then(db => {
  console.log("database connected");
  app.set("db", db);
});

app.post("/auth/signup", (req, res, next) => {
  // set db = to req.app.get("db") so we have access to the database
  const db = req.app.get("db");
  // destructure the email and password coming from the body of the request
  const { email, password } = req.body;

  db.check_user_exists(email).then(user => {
    if (user.length) {
      res.status(400).send("Email already exists, did you mean to login?");
    } else {
      const saltRounds = 12;
      bcrypt.genSalt(saltRounds).then(salt => {
        bcrypt.hash(password, salt).then(hashedPassword => {
          db.create_user([email, hashedPassword]).then(([createdUser]) => {
            req.session.user = {
              id: createdUser.id,
              email: createdUser.email
            };
            res.status(200).send(req.session.user);
          });
        });
      });
    }
  });
});

app.post("/auth/login", (req, res, next) => {
  const db = req.app.get("db");
  const { email, password } = req.body;

  db.check_user_exists(email).then(([foundUser]) => {
    if (!foundUser) {
      res.status(400).send("incorrect email/password");
    } else {
      console.log(password, foundUser);
      bcrypt
        .compare(password, foundUser.user_password)
        .then(isAuthenticated => {
          if (isAuthenticated) {
            req.session.user = {
              id: foundUser.id,
              email: foundUser.email
            };
            res.status(200).send(req.session.user);
          } else {
            res.status(200).send("http://bit.ly/unathorized");
          }
        });
    }
  });
});

app.listen(SERVER_PORT, () => {
  console.log(`Listening on port: ${SERVER_PORT}`);
});
