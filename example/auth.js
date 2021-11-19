var passport = require("passport");
var Strategy = require("passport-google-one-tap").GoogleOneTapStrategy;
var db = require("./db");

module.exports = function () {
  // Configure the Google One Tap strategy for use by Passport.
  //
  // Google One Tap strategy require a `verify` function which receives the
  // with the user's profile. The function must invoke `done`
  // with a user object, which will be set at `req.user` in route handlers after
  // authentication.
  passport.use(
    new Strategy(
      {
        consumerKey: process.env["GOOGLE_CLIENT_ID"],
        consumerSecret: process.env["GOOGLE_CLIENT_SECRET"],
      },
      function (profile, done) {
        if (!profile) {
          return done(undefined, undefined);
        }

        db.get(
          "SELECT * FROM federated_credentials WHERE provider = ? AND subject = ?",
          [profile.provider, profile.id],
          function (err, row) {
            if (err) {
              return done(err);
            }

            if (!row) {
              db.run(
                "INSERT INTO users (email, name) VALUES (?, ?)",
                [profile.emails[0].value, profile.displayName],
                function (err) {
                  if (err) {
                    return done(err);
                  }

                  var id = this.lastID;
                  db.run(
                    "INSERT INTO federated_credentials (provider, subject, user_id) VALUES (?, ?, ?)",
                    [profile.provider, profile.id, id],
                    function (err) {
                      if (err) {
                        return done(err);
                      }

                      var user = {
                        id: id.toString(),
                        name: profile.displayName,
                        email: profile.emails[0].value,
                      };

                      return done(undefined, user);
                    }
                  );
                }
              );
            } else {
              db.get(
                "SELECT rowid AS id, email, name FROM users WHERE rowid = ?",
                [row.user_id],
                function (err, row) {
                  if (err) {
                    return done(err);
                  }

                  if (!row) {
                    return done(new Error("DB not consistent"));
                  }

                  var user = {
                    id: row.id.toString(),
                    email: row.email,
                    name: row.name,
                  };

                  return done(undefined, user);
                }
              );
            }
          }
        );
      }
    )
  );

  // Configure Passport authenticated session persistence.
  //
  // In order to restore authentication state across HTTP requests, Passport needs
  // to serialize users into and deserialize users out of the session. In a
  // production-quality application, this would typically be as simple as
  // supplying the user ID when serializing, and querying the user record by ID
  // from the database when deserializing.
  passport.serializeUser(function (user, cb) {
    cb(undefined, user.id);
  });

  passport.deserializeUser(function (obj, cb) {
    db.get(
      "SELECT rowid AS id, email, name FROM users WHERE rowid = ?",
      [obj],
      function (err, row) {
        if (err) {
          return cb(err);
        }

        if (!row) {
          return cb();
        }

        var user = {
          id: row.id.toString(),
          email: row.email,
          name: row.name,
        };

        return cb(undefined, user);
      }
    );
  });
};
