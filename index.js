require("./utils.js");

require("dotenv").config();
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");
const { name } = require("ejs");

const expireTime = 1 * 60 * 60 * 1000; // Hours * Minutes * Seconds * Milliseconds

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

app.set("view engine", "ejs");

// MongoDB Database
var { database } = include("database.js");

const userCollection = database.db(mongodb_database).collection("users");

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
  crypto: {
    secret: mongodb_session_secret,
  },
});

app.use(
  session({
    secret: node_session_secret,
    store: mongoStore, //default is memory store
    saveUninitialized: false,
    resave: true,
  })
);

// Main page
app.get("/", (req, res) => {
  if (req.session.user) {
    var name = req.query.user;
    res.render("loggedin");
  } else {
    res.render("index");
  }
});

// NoSQL Protection
app.get("/nosql-injection", async (req, res) => {
  var name = req.query.user;

  if (!name) {
    res.send(
      `<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`
    );
    return;
  }
  console.log("name: " + name);

  const schema = Joi.string().max(20).required();
  const validationResult = schema.validate(name);

  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.render("errorNoSQL");
    return;
  }

  const result = await userCollection
    .find({ name: name })
    .project({ name: 1, password: 1, _id: 1 })
    .toArray();

  console.log(result);

  res.render("NoSQLverified");
});

// Signup / Signout / Login / Logout
app.get("/signup", (req, res) => {
  res.render("signup");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/submitUser", async (req, res) => {
  var email = req.body.email;
  var name = req.body.name;
  var password = req.body.password;

  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().max(20).required(),
    name: Joi.string().alphanum().max(20).required()
  });

  const validationResult = schema.validate({ email, password, name });
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.redirect("/signup");
    return;
  }

  var hashedPassword = await bcrypt.hash(password, saltRounds);

  await userCollection.insertOne({
    name: name,
    password: hashedPassword,
    email: email,
    usertype: "user"
  });
  console.log("Inserted user");

  req.session.authenticated = true;
  req.session.name = name;
  req.session.email = email;
  req.session.usertype = "user";

  res.redirect("/loggedin");
});

app.post("/loggingin", async (req, res) => {
  var email = req.body.email;
  var password = req.body.password;
  
  const schema = Joi.string().max(20).required();
  const validationResult = schema.validate(email);
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.redirect("/login");
    return;
  }
  
  const result = await userCollection.find({email: email}).project({ name: 1, email: 1, password: 1, _id: 1, usertype: 1 }).toArray();
  
  console.log(result);
  if (result.length != 1) {
    console.log("This user cannot be found");
    res.redirect("/login");
    return;
  }
  if (await bcrypt.compare(password, result[0].password)) {
    console.log("right password");
    req.session.authenticated = true;
    req.session.email = email;
    req.session.name = result[0].name;
    req.session.usertype = result[0].usertype;
    req.session.cookie.maxAge = expireTime;

    res.redirect("/loggedin");
    return;
  } else {
    console.log("You have entered an invalid password.");
    res.redirect("/submiterror");
    return;
  }
});

app.get("/loggedin", (req, res) => {
  const name = req.session.name;
  if (!req.session.authenticated) {
    console.log("Please log in.");
    res.redirect("/login");
  }
  res.render("loggedin", { name: name });
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

app.get("/members", (req, res) => {
  const name = req.session.name;
  if (!req.session.authenticated) {
    res.redirect("/");
    return;
  }

  res.render("members", { name: req.session.name });
});

// Session Validation
function isValidSession(req) {
  if (req.session.authenticated) {
    return true;
  }
  return false;
}

function sessionValidation(req, res, next) {
  if (isValidSession(req)) {
    next();
  } else {
    res.redirect("/login");
  }
}

// Admin Functions
function isAdmin(req) {
  console.log(req.session.usertype);
  if (req.session.usertype == "admin") {
    return true;
  }
  return false;
}

function adminAuthorization(req, res, next) {
  if (!isAdmin(req)) {
    res.status(403);
    res.render("403", {
      error: "Error 403 - You are not authorized.",
    });
    return;
  } else {
    res.render("/admin");
  }
}

app.get("/admin", sessionValidation, adminAuthorization, async (req, res) => {
  const result = await userCollection
    .find()
    .project({ name: 1, _id: 1, usertype: 1 })
    .toArray();
  res.render("admin", { users: result });
});

app.post("/promote", async (req, res) => {
  var rname = req.body.name;

  await userCollection.updateOne(
    { name: name },
    { $set: { usertype: "admin" } }
  );
  res.redirect("/admin");
});

app.post("/demote", async (req, res) => {
  var name = req.body.name;

  await userCollection.updateOne(
    { name: name },
    { $set: { usertype: "user" } }
  );
  res.redirect("/admin");
});

app.use(express.static(__dirname + "/public"));

app.use(express.urlencoded({extended: false}));

app.get("*", (req, res) => {
  res.status(404);
  res.render("404");
});

app.listen(port, () => {
  console.log("Node application listening on port " + port);
});
