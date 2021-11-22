# passport-google-one-tap

[Passport](http://passportjs.org/) strategy for authenticating with
[Google One Tap](https://developers.google.com/identity/one-tap).

This module lets you authenticate using Google One Tap in your Node.js applications.
By plugging into Passport, Google One Tap authentication can be easily and
unobtrusively integrated into any application or framework that supports
[Connect](http://www.senchalabs.org/connect/)-style middleware, including
[Express](http://expressjs.com/).

[![npm](https://img.shields.io/npm/v/passport-google-one-tap.svg)](https://www.npmjs.com/package/passport-google-one-tap)
[![MIT license](https://img.shields.io/npm/l/diod)](./LICENSE)
[![Build status](https://github.com/Genially/passport-google-one-tap/actions/workflows/qa.yml/badge.svg)](https://github.com/Genially/passport-google-one-tap/actions)
[![codecov](https://codecov.io/gh/Genially/passport-google-one-tap/branch/main/graph/badge.svg?token=fOgYwD6XoD)](https://codecov.io/gh/Genially/passport-google-one-tap)

## Install

```bash
npm install passport-google-one-tap
```

## Usage

### Create an Application

Before using `passport-google-one-tap`, you must register an application with
Google. If you have not already done so, a new project can be created in the
[Google Developers Console](https://console.developers.google.com/).
Your application will be issued a client ID and client secret, which need to be
provided to the strategy.

### Configure client side

The client side configuration is not covered by this plugin, you can follow
the official [Google One Tap Guidelines](https://developers.google.com/identity/gsi/web/guides/display-google-one-tap).

The client ID used in the front-end must be the same used in
the strategy configuration and the login uri must be the same that you will configure
in the [Authenticate Requests](#authenticate-requests) section.

Minimal example:

```html
<script src="https://accounts.google.com/gsi/client" async defer></script>
<div
  id="g_id_onload"
  data-client_id="YOUR_GOOGLE_CLIENT_ID"
  data-login_uri="https://your.domain/auth/one-tap/callback"
></div>
```

### Configure Strategy

The Google One Tap authentication strategy verifies the
Google ID token on your server side and retrieves the user information.
The client ID and secret obtained when creating an
application are supplied as options when creating the strategy. The strategy
also requires a `verify` callback, which receives the `profile` with the authenticated user's
Google profile. The `verify` callback must call `done` providing a user to
complete authentication.

```javascript
var GoogleOneTapStrategy =
  require("passport-google-one-tap").GoogleOneTapStrategy;

passport.use(
  new GoogleOneTapStrategy(
    {
      clientID: GOOGLE_CLIENT_ID, // your google client ID
      clientSecret: GOOGLE_CLIENT_SECRET, // your google client secret
      verifyCsrfToken: false, // whether to validate the csrf token or not
    },
    function (profile, done) {
      // Here your app code, for example:
      User.findOrCreate({ googleId: profile.id }, function (err, user) {
        return done(err, user);
      });
    }
  )
);
```

#### Authenticate Requests

Use `passport.authenticate()`, specifying the `'google-one-tap'` strategy, to
authenticate requests.

For example, as route middleware in an [Express](http://expressjs.com/)
application:

```javascript
app.post(
  "/auth/one-tap/callback",
  passport.authenticate(
    "google-one-tap",
    { failureRedirect: "/login" },
    (err, user) => {
      // Do whatever you need
    }
  ),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect("/");
  }
);
```

## Examples

Developers using the popular [Express](http://expressjs.com/) web framework can
refer to an [example](https://github.com/Genially/passport-google-one-tap/tree/main/example#readme)
as a starting point for their own web applications.

## License

passport-google-one-tap is released under the MIT license:

MIT License

Copyright (c) 2021 Genially Web S.L.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
