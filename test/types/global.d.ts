import type { Request } from "express";
import { Profile } from "passport";
import { Strategy } from "passport-strategy";

interface ChaiPassportStrategy {
  use(strategy: Strategy): ChaiPassportStrategy;
  success(
    callback: (profile: Profile, info?: object) => void
  ): ChaiPassportStrategy;
  error(callback: (e: Error) => void): ChaiPassportStrategy;
  fail(
    callback: (challenge: string, status: number) => void
  ): ChaiPassportStrategy;
  request(callback: (request: Request) => void): ChaiPassportStrategy;
  authenticate: () => void;
}

declare global {
  namespace Chai {
    interface ChaiStatic {
      passport: ChaiPassportStrategy;
    }
  }
}

declare const chaiPassportStrategy: Chai.ChaiPlugin;
export = chaiPassportStrategy;
