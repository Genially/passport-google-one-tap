import type { Request } from "express";
import { OAuth2Client } from "google-auth-library";
import { Profile } from "passport";
import { Strategy } from "passport-strategy";

interface DoneFunction {
  (error: unknown, user?: unknown, msg?: string): void;
}

type VerifyFunction = (profile: Profile, done: DoneFunction) => void;

type VerifyFunctionWithRequest = (
  req: Request,
  profile: Profile,
  done: DoneFunction
) => void;

interface GoogleOneTapStrategyOptionBase {
  clientID?: string;
  clientSecret?: string;
  redirectUri?: string;
  verifyCsrfToken?: boolean;
}

interface GoogleOneTapStrategyOption extends GoogleOneTapStrategyOptionBase {
  passReqToCallback?: false;
}

interface GoogleOneTapStrategyOptionWithRequest
  extends GoogleOneTapStrategyOptionBase {
  passReqToCallback: true;
}

export class GoogleOneTapStrategy extends Strategy {
  public name = "google-one-tap";
  private readonly options:
    | GoogleOneTapStrategyOption
    | GoogleOneTapStrategyOptionWithRequest;
  private readonly client: OAuth2Client;
  private readonly verify:
    | {
        passReqToCallback: false;
        func: VerifyFunction;
      }
    | {
        passReqToCallback: true;
        func: VerifyFunctionWithRequest;
      };

  public constructor(verify: VerifyFunction);
  public constructor(
    options: GoogleOneTapStrategyOption,
    verify: VerifyFunction
  );
  public constructor(
    options: GoogleOneTapStrategyOptionWithRequest,
    verify: VerifyFunctionWithRequest
  );
  public constructor(
    optionsParam:
      | GoogleOneTapStrategyOption
      | GoogleOneTapStrategyOptionWithRequest
      | VerifyFunction,
    verifyParam?: VerifyFunction | VerifyFunctionWithRequest
  ) {
    super();
    const withoutOptions = typeof optionsParam === "function";
    const options = withoutOptions ? {} : optionsParam;
    const verify = withoutOptions ? optionsParam : verifyParam;
    if (typeof verify !== "function") {
      throw new Error("GoogleOneTapStrategy requires a verify callback");
    }

    const verifyCsrfToken =
      options.verifyCsrfToken === undefined ? true : options.verifyCsrfToken;
    this.options = { ...options, verifyCsrfToken };
    this.client = new OAuth2Client(
      options.clientID,
      options.clientSecret,
      options.redirectUri
    );
    this.verify = options.passReqToCallback
      ? {
          passReqToCallback: true,
          func: verify as VerifyFunctionWithRequest,
        }
      : {
          passReqToCallback: false,
          func: verify as VerifyFunction,
        };
  }

  public authenticate(req: Request): void {
    if (this.options.verifyCsrfToken && !this.isCsrfValid(req)) {
      return;
    }

    const verified: DoneFunction = (err, user, info): void => {
      if (err) {
        const error = err instanceof Error ? err : new Error(String(err));
        return this.error(error);
      }

      if (!user) {
        return this.fail(info, 401);
      }

      this.success(user);
    };

    this.verifyToken(req)
      .then((profile) => {
        if (!profile) {
          return this.fail("No user logged.", 401);
        }

        if (this.verify.passReqToCallback) {
          this.verify.func(req, profile, verified);
        } else {
          this.verify.func(profile, verified);
        }
      })
      .catch((err) => {
        this.error(err instanceof Error ? err : new Error(String(err)));
      });
  }

  private isCsrfValid(req: Request): boolean {
    const csrfTokenCookie = req.cookies["g_csrf_token"];

    if (!csrfTokenCookie) {
      this.fail("No CSRF token in Cookie.", 400);

      return false;
    }

    const csrfTokenBody = req.body["g_csrf_token"];

    if (!csrfTokenBody) {
      this.fail("No CSRF token in post body.", 400);

      return false;
    }

    if (csrfTokenBody !== csrfTokenCookie) {
      this.fail("Failed to verify double submit cookie.", 400);

      return false;
    }

    return true;
  }

  private async verifyToken(req: Request): Promise<Profile | undefined> {
    const token = req.body["credential"];

    if (!token) {
      return;
    }

    const ticket = await this.client.verifyIdToken({
      idToken: token,
      audience: this.options.clientID,
    });
    const payload = ticket.getPayload();

    if (!payload) {
      return;
    }

    const name =
      payload.family_name && payload.given_name
        ? {
            familyName: payload.family_name,
            givenName: payload.given_name,
          }
        : undefined;

    return {
      id: payload.sub,
      displayName: payload.name || "",
      name,
      provider: this.name,
      emails: payload.email ? [{ value: payload.email }] : [],
      photos: payload.picture ? [{ value: payload.picture }] : [],
    };
  }
}
