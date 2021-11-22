import chai, { expect } from "chai";
import passport from "chai-passport-strategy";
import { LoginTicket, OAuth2Client } from "google-auth-library";
import { GoogleOneTapStrategy } from "../src/index";

chai.use(passport);

describe("Strategy", () => {
  describe("construction", () => {
    it("is named google-one-tap", () => {
      // Arrange & Act
      const strategy = new GoogleOneTapStrategy(() => {
        // Do nothing
      });

      // Assert
      expect(strategy.name).to.equal("google-one-tap");
    });

    it("can not be constructed without verify function", () => {
      // Act & Assert
      expect(() => new (GoogleOneTapStrategy as any)()).to.throw(Error);

      // Act & Assert
      expect(
        () =>
          new (GoogleOneTapStrategy as any)({
            clientID: "CLIENT_ID",
            clientSecret: "CLIENT_SECRET",
          })
      ).to.throw(Error);
    });
  });

  describe("csrf token validation", () => {
    it("fails if cookie token is not present", (done) => {
      // Arrange
      const strategy = new GoogleOneTapStrategy(
        {
          clientID: "CLIENT_ID",
          clientSecret: "CLIENT_SECRET",
          verifyCsrfToken: true,
        },
        () => {
          // Do nothing
        }
      );

      // Act & Assert
      chai.passport
        .use(strategy)
        .request((req) => {
          req.cookies = {};
          req.body = { g_csrf_token: 1234 };
        })
        .fail((challenge, status) => {
          expect(challenge).to.equal("No CSRF token in Cookie.");
          expect(status).to.equal(400);
          done();
        })
        .authenticate();
    });

    it("fails if token is not present in body", (done) => {
      // Arrange
      const strategy = new GoogleOneTapStrategy(
        {
          clientID: "CLIENT_ID",
          clientSecret: "CLIENT_SECRET",
          verifyCsrfToken: true,
        },
        () => {
          // Do nothing
        }
      );

      // Act & Assert
      chai.passport
        .use(strategy)
        .request((req) => {
          req.cookies = { g_csrf_token: 1234 };
          req.body = {};
        })
        .fail((challenge, status) => {
          expect(challenge).to.equal("No CSRF token in post body.");
          expect(status).to.equal(400);
          done();
        })
        .authenticate();
    });

    it("fails if token is not equal in body and cookie", (done) => {
      // Arrange
      const strategy = new GoogleOneTapStrategy(
        {
          clientID: "CLIENT_ID",
          clientSecret: "CLIENT_SECRET",
          verifyCsrfToken: true,
        },
        () => {
          // Do nothing
        }
      );

      // Act & Assert
      chai.passport
        .use(strategy)
        .request((req) => {
          req.cookies = { g_csrf_token: 1234 };
          req.body = { g_csrf_token: 4321 };
        })
        .fail((challenge, status) => {
          expect(challenge).to.equal("Failed to verify double submit cookie.");
          expect(status).to.equal(400);
          done();
        })
        .authenticate();
    });

    it("does not exist CSRF issue if token is correct", (done) => {
      // Arrange
      const strategy = new GoogleOneTapStrategy(
        {
          clientID: "CLIENT_ID",
          clientSecret: "CLIENT_SECRET",
          verifyCsrfToken: true,
        },
        () => {
          // Do nothing
        }
      );

      // Act & Assert
      chai.passport
        .use(strategy)
        .request((req) => {
          req.cookies = { g_csrf_token: 1234 };
          req.body = { g_csrf_token: 1234 };
        })
        .fail((challenge, status) => {
          expect(challenge).to.equal("No user logged.");
          expect(status).to.equal(401);
          done();
        })
        .authenticate();
    });

    it("does not exist CSRF issue if token is not verified", (done) => {
      // Arrange
      const strategy = new GoogleOneTapStrategy(
        {
          clientID: "CLIENT_ID",
          clientSecret: "CLIENT_SECRET",
          verifyCsrfToken: false,
        },
        () => {
          // Do nothing
        }
      );

      // Act & Assert
      chai.passport
        .use(strategy)
        .request((req) => {
          req.cookies = {};
          req.body = {};
        })
        .fail((challenge, status) => {
          expect(challenge).to.equal("No user logged.");
          expect(status).to.equal(401);
          done();
        })
        .authenticate();
    });
  });

  describe("authentication", () => {
    it("does not authenticate if there is no credential", (done) => {
      // Arrange
      const strategy = new GoogleOneTapStrategy(
        {
          clientID: "CLIENT_ID",
          clientSecret: "CLIENT_SECRET",
        },
        () => {
          // Do nothing
        }
      );
      const crsfToken = 1234;

      // Act & Assert
      chai.passport
        .use(strategy)
        .request((req) => {
          req.cookies = { g_csrf_token: crsfToken };
          req.body = { g_csrf_token: crsfToken, credential: undefined };
        })
        .fail((challenge, status) => {
          expect(challenge).to.equal("No user logged.");
          expect(status).to.equal(401);
          done();
        })
        .authenticate();
    });

    it("throws error if google client lib throws error verifying token", (done) => {
      // Arrange
      const crsfToken = 1234;
      const credential = "credential_string";
      const clientID = "CLIENT_ID";
      OAuth2Client.prototype.verifyIdToken = (options) => {
        expect(options.idToken).to.equal(credential);
        expect(options.audience).to.equal(clientID);

        throw new Error("Mock error");
      };
      const strategy = new GoogleOneTapStrategy(
        {
          clientID,
          clientSecret: "CLIENT_SECRET",
        },
        () => {
          // Do nothing
        }
      );

      // Act & Assert
      chai.passport
        .use(strategy)
        .request((req) => {
          req.cookies = { g_csrf_token: crsfToken };
          req.body = {
            g_csrf_token: crsfToken,
            credential,
          };
        })
        .error((e) => {
          expect(e.message).to.equal("Mock error");
          done();
        })
        .authenticate();
    });

    it("throws error if google client lib throws error getting the ticket payload", (done) => {
      // Arrange
      const crsfToken = 1234;
      const credential = "credential_string";
      const clientID = "CLIENT_ID";
      OAuth2Client.prototype.verifyIdToken = (options) => {
        expect(options.idToken).to.equal(credential);
        expect(options.audience).to.equal(clientID);

        return Promise.resolve({
          getPayload: () => {
            throw "Mock error";
          },
        } as unknown as LoginTicket);
      };
      const strategy = new GoogleOneTapStrategy(
        {
          clientID,
          clientSecret: "CLIENT_SECRET",
        },
        () => {
          // Do nothing
        }
      );

      // Act & Assert
      chai.passport
        .use(strategy)
        .request((req) => {
          req.cookies = { g_csrf_token: crsfToken };
          req.body = {
            g_csrf_token: crsfToken,
            credential,
          };
        })
        .error((e) => {
          expect(e.message).to.equal("Mock error");
          done();
        })
        .authenticate();
    });

    it("fails login if the ticket payload is empty", (done) => {
      // Arrange
      const crsfToken = 1234;
      const credential = "credential_string";
      const clientID = "CLIENT_ID";
      OAuth2Client.prototype.verifyIdToken = (options) => {
        expect(options.idToken).to.equal(credential);
        expect(options.audience).to.equal(clientID);

        return Promise.resolve({
          getPayload: () => undefined,
        } as unknown as LoginTicket);
      };
      const strategy = new GoogleOneTapStrategy(
        {
          clientID,
          clientSecret: "CLIENT_SECRET",
        },
        () => {
          // Do nothing
        }
      );

      // Act & Assert
      chai.passport
        .use(strategy)
        .request((req) => {
          req.cookies = { g_csrf_token: crsfToken };
          req.body = {
            g_csrf_token: crsfToken,
            credential,
          };
        })
        .fail((challenge, status) => {
          expect(challenge).to.equal("No user logged.");
          expect(status).to.equal(401);
          done();
        })
        .authenticate();
    });

    it("authenticates if the google lib returns a valid payload", (done) => {
      // Arrange
      const crsfToken = 1234;
      const credential = "credential_string";
      const clientID = "CLIENT_ID";
      OAuth2Client.prototype.verifyIdToken = (options) => {
        expect(options.idToken).to.equal(credential);
        expect(options.audience).to.equal(clientID);

        return Promise.resolve({
          getPayload: () => ({
            sub: "userId",
            name: "UserName",
            email: "user@email.com",
          }),
        } as unknown as LoginTicket);
      };
      const strategy = new GoogleOneTapStrategy(
        {
          clientID,
          clientSecret: "CLIENT_SECRET",
        },
        (profile, verify) => {
          verify(undefined, profile);
        }
      );

      // Act & Assert
      chai.passport
        .use(strategy)
        .request((req) => {
          req.cookies = { g_csrf_token: crsfToken };
          req.body = {
            g_csrf_token: crsfToken,
            credential,
          };
        })
        .success((profile) => {
          expect(profile.id).to.equal("userId");
          expect(profile.provider).to.equal("google-one-tap");
          expect(profile.displayName).to.equal("UserName");
          expect(profile.emails?.[0]?.value).to.equal("user@email.com");
          done();
        })
        .authenticate();
    });

    it("authenticates if the google lib returns a minimal payload", (done) => {
      // Arrange
      const crsfToken = 1234;
      const credential = "credential_string";
      const clientID = "CLIENT_ID";
      OAuth2Client.prototype.verifyIdToken = (options) => {
        expect(options.idToken).to.equal(credential);
        expect(options.audience).to.equal(clientID);

        return Promise.resolve({
          getPayload: () => ({
            sub: "userId",
          }),
        } as unknown as LoginTicket);
      };
      const strategy = new GoogleOneTapStrategy(
        {
          clientID,
          clientSecret: "CLIENT_SECRET",
        },
        (profile, verify) => {
          verify(undefined, profile);
        }
      );

      // Act & Assert
      chai.passport
        .use(strategy)
        .request((req) => {
          req.cookies = { g_csrf_token: crsfToken };
          req.body = {
            g_csrf_token: crsfToken,
            credential,
          };
        })
        .success((profile) => {
          expect(profile.id).to.equal("userId");
          expect(profile.provider).to.equal("google-one-tap");
          expect(profile.displayName).to.equal("");
          expect(profile.emails?.length).to.equal(0);
          done();
        })
        .authenticate();
    });

    it("authenticates if the google lib returns a full valid payload", (done) => {
      // Arrange
      const crsfToken = 1234;
      const credential = "credential_string";
      const clientID = "CLIENT_ID";
      OAuth2Client.prototype.verifyIdToken = (options) => {
        expect(options.idToken).to.equal(credential);
        expect(options.audience).to.equal(clientID);

        return Promise.resolve({
          getPayload: () => ({
            sub: "userId",
            name: "UserName",
            email: "user@email.com",
            picture: "https://picture.com/picture.png",
            family_name: "Johnny",
            given_name: "John",
          }),
        } as unknown as LoginTicket);
      };
      const strategy = new GoogleOneTapStrategy(
        {
          clientID,
          clientSecret: "CLIENT_SECRET",
        },
        (profile, verify) => {
          verify(undefined, profile);
        }
      );

      // Act & Assert
      chai.passport
        .use(strategy)
        .request((req) => {
          req.cookies = { g_csrf_token: crsfToken };
          req.body = {
            g_csrf_token: crsfToken,
            credential,
          };
        })
        .success((profile) => {
          expect(profile.id).to.equal("userId");
          expect(profile.provider).to.equal("google-one-tap");
          expect(profile.displayName).to.equal("UserName");
          expect(profile.emails?.[0]?.value).to.equal("user@email.com");
          expect(profile.photos?.[0]?.value).to.equal(
            "https://picture.com/picture.png"
          );
          expect(profile.name?.familyName).to.equal("Johnny");
          expect(profile.name?.givenName).to.equal("John");
          done();
        })
        .authenticate();
    });

    it("authenticates if the google lib returns a valid payload and returns request if asked for it", (done) => {
      // Arrange
      const crsfToken = 1234;
      const credential = "credential_string";
      const clientID = "CLIENT_ID";
      OAuth2Client.prototype.verifyIdToken = (options) => {
        expect(options.idToken).to.equal(credential);
        expect(options.audience).to.equal(clientID);

        return Promise.resolve({
          getPayload: () => ({
            sub: "userId",
            name: "UserName",
            email: "user@email.com",
          }),
        } as unknown as LoginTicket);
      };
      const strategy = new GoogleOneTapStrategy(
        {
          clientID,
          clientSecret: "CLIENT_SECRET",
          passReqToCallback: true,
        },
        (request, profile, verify) => {
          expect(request.body?.credential).to.equal(credential);
          verify(undefined, profile);
        }
      );

      // Act & Assert
      chai.passport
        .use(strategy)
        .request((req) => {
          req.cookies = { g_csrf_token: crsfToken };
          req.body = {
            g_csrf_token: crsfToken,
            credential,
          };
        })
        .success((profile) => {
          expect(profile.id).to.equal("userId");
          expect(profile.provider).to.equal("google-one-tap");
          expect(profile.displayName).to.equal("UserName");
          expect(profile.emails?.[0]?.value).to.equal("user@email.com");
          done();
        })
        .authenticate();
    });

    it("throws error if the callback funtion throws error", (done) => {
      // Arrange
      const crsfToken = 1234;
      const credential = "credential_string";
      const clientID = "CLIENT_ID";
      OAuth2Client.prototype.verifyIdToken = (options) => {
        expect(options.idToken).to.equal(credential);
        expect(options.audience).to.equal(clientID);

        return Promise.resolve({
          getPayload: () => ({
            sub: "userId",
            name: "UserName",
            email: "user@email.com",
          }),
        } as unknown as LoginTicket);
      };
      const strategy = new GoogleOneTapStrategy(
        {
          clientID,
          clientSecret: "CLIENT_SECRET",
        },
        (profile, verify) => {
          verify(new Error("Verify Error"), profile);
        }
      );

      // Act & Assert
      chai.passport
        .use(strategy)
        .request((req) => {
          req.cookies = { g_csrf_token: crsfToken };
          req.body = {
            g_csrf_token: crsfToken,
            credential,
          };
        })
        .error((err) => {
          expect(err.message).to.equal("Verify Error");
          done();
        })
        .authenticate();
    });

    it("throws error if the callback funtion returns error", (done) => {
      // Arrange
      const crsfToken = 1234;
      const credential = "credential_string";
      const clientID = "CLIENT_ID";
      OAuth2Client.prototype.verifyIdToken = (options) => {
        expect(options.idToken).to.equal(credential);
        expect(options.audience).to.equal(clientID);

        return Promise.resolve({
          getPayload: () => ({
            sub: "userId",
            name: "UserName",
            email: "user@email.com",
          }),
        } as unknown as LoginTicket);
      };
      const strategy = new GoogleOneTapStrategy(
        {
          clientID,
          clientSecret: "CLIENT_SECRET",
        },
        (profile, verify) => {
          verify("Verify Error", profile);
        }
      );

      // Act & Assert
      chai.passport
        .use(strategy)
        .request((req) => {
          req.cookies = { g_csrf_token: crsfToken };
          req.body = {
            g_csrf_token: crsfToken,
            credential,
          };
        })
        .error((err) => {
          expect(err.message).to.equal("Verify Error");
          done();
        })
        .authenticate();
    });

    it("returns not logged if the verify function does not return usser", (done) => {
      // Arrange
      const crsfToken = 1234;
      const credential = "credential_string";
      const clientID = "CLIENT_ID";
      OAuth2Client.prototype.verifyIdToken = (options) => {
        expect(options.idToken).to.equal(credential);
        expect(options.audience).to.equal(clientID);

        return Promise.resolve({
          getPayload: () => ({
            sub: "userId",
            name: "UserName",
            email: "user@email.com",
          }),
        } as unknown as LoginTicket);
      };
      const strategy = new GoogleOneTapStrategy(
        {
          clientID,
          clientSecret: "CLIENT_SECRET",
        },
        (_profile, verify) => {
          verify(undefined, undefined, "Can not found user");
        }
      );

      // Act & Assert
      chai.passport
        .use(strategy)
        .request((req) => {
          req.cookies = { g_csrf_token: crsfToken };
          req.body = {
            g_csrf_token: crsfToken,
            credential,
          };
        })
        .fail((challenge, status) => {
          expect(challenge).to.equal("Can not found user");
          expect(status).to.equal(401);
          done();
        })
        .authenticate();
    });
  });
});
