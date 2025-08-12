import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import session from "express-session";
import env from "dotenv";

const app = express();
const port = process.env.PORT || 3000;
const saltRounds = 10;
env.config();


app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24, // 1 day
    },
  })
);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(passport.initialize());
app.use(passport.session());

//const db = new pg.Client({
 // user: process.env.DB_USER,
 // host: process.env.DB_HOST,
 // database: process.env.DB_DATABASE,
 //password: process.env.DB_PASSWORD,
 //port: process.env.DB_PORT,
//});

const db = new pg.Client({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

db.connect();

app.get("/", (req, res) => {
  res.render("index.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/journal",
    failureRedirect: "/login",
  })
);

app.post("/register", async (req, res) => {
  const email = req.body.email;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
    if (checkResult.rows.length > 0) {
      res.redirect("/login");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.log(err);
        } else {
          const result = await db.query(
            "INSERT INTO users (email, password) VALUES ($1,$2) RETURNING *",
            [email, hash]
          );
          const newUser = result.rows[0];
          req.login(newUser, (err) => {
            if (err) {
              console.log(err);
              return res.redirect("/login");
            }
            res.redirect("/journal");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/journal",
    failureRedirect: "/register",
  })
);

app.get("/journal", async (req, res) => {
  if (req.isAuthenticated()) {
    const entries = await db.query("SELECT * FROM entries WHERE user_id = $1", [
      req.user.id,
    ]);
    res.render("journal.ejs", { entries: entries.rows });
    console.log(req.user);
  } else {
    res.redirect("/login");
  }
});

app.post("/newEntry", async (req, res) => {
  if (req.isAuthenticated()) {
    const userId = req.user.id;
    const entryTitle = req.body.entryTitle;
    const entryContent = req.body.entryContent;

    try {
      await db.query(
        "INSERT INTO entries (user_id, title, content) VALUES ($1, $2, $3)",
        [userId, entryTitle, entryContent]
      );
      res.redirect("/journal");
    } catch (err) {
      console.log(err);
    }
  } else {
    res.redirect("/login");
  }
});

app.post("/journal/delete/:id", async (req, res) => {
  if (req.isAuthenticated()) {
    const entryId = req.params.id;
    const userId = req.user.id;
    try {
      await db.query("DELETE FROM entries WHERE id = $1 AND user_id = $2", [
        entryId,
        userId,
      ]);
      res.redirect("/journal");
    } catch (err) {
      console.log(err);
    }
  } else {
    res.redirect("/journal");
  }
});

app.post("/journal/edit/:id", async (req, res) => {
  if (req.isAuthenticated()) {
    const entryId = req.params.id;
    const userId = req.user.id;
    const title = req.body.editEntryTitle;
    const content = req.body.editEntryContent;
    try {
      await db.query(
        "UPDATE entries SET title = $1, content = $2 WHERE id = $3 AND user_id = $4",
        [title, content, entryId, userId]
      );
      res.redirect("/journal");
    } catch (err) {
      console.log(err);
    }
  } else {
    res.redirect("/journal");
  }
});

passport.use(
  "local",
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1", [
        username,
      ]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedPassword = user.password;
        bcrypt.compare(password, storedPassword, (err, valid) => {
          if (err) {
            return cb(err);
          } else {
            if (valid) {
              return cb(null, user);
            } else {
              return cb(null, false);
            }
          }
        });
      } else {
        return cb(null, false);
      }
    } catch (err) {
      console.log(err);
    }
  })
);

passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },

    async (accessToken, refreshToken, profile, cb) => {
      try {
        const result = await db.query("SELECT * FROM users WHERE email = $1", [
          profile.email,
        ]);

        if (result.rows.length === 0) {
          const newUser = await db.query(
            "INSERT INTO users (email, password, google_id) VALUES ($1, $2, $3) RETURNING *",
            [profile.email, "google", profile.id]
          );
          return cb(null, newUser.rows[0]);
        } else {
          return cb(null, result.rows[0]);
        }
      } catch (err) {
        return cb(err);
      }
    }
  )
);

passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
