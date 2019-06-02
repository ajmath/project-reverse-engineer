import { Request } from "express";
import { authenticate } from "./auth";
import { sign, SignOptions } from "jsonwebtoken";
import * as portfinder from "portfinder";
import * as fs from "fs";
import * as express from "express";
import { Server } from "http";

function mockRequest(authorizationHeader?: string): Request {
  return {
    headers: {
      authorization: authorizationHeader,
    }
  } as any as Request;
}

const testAud = "test-aud";
process.env.AUDIENCE = testAud;

describe("auth.ts", () => {

  describe("non auth method specific", () => {
    it("should revoke request without valid authentication method", async () => {
      const req = mockRequest("Bad auth method");
      const result = await authenticate(req);
      expect(result).toEqual({
        authenticated: false,
        message: "Unsupported Authentication Method",
        status: 403
      });
    });

    it("should revoke request without auth header", async () => {
      const req = mockRequest(undefined);
      const result = await authenticate(req);
      expect(result).toEqual({
        authenticated: false,
        message: "Authentication header is empty",
        status: 403
      });
    });
  });

  describe("basic auth", () => {

    it("should revoke request with invalid basic auth", async () => {
      const req = mockRequest("Basic InvalidBasicAuth");
      const result = await authenticate(req);
      expect(result).toEqual({
        authenticated: false,
        message: "Basic Auth Error",
        status: 403
      });
    });

    it("should accept basic auth with hard-coded password", async () => {
      const token = Buffer.from("fill in the password").toString('base64');
      const req = mockRequest(`Basic ${token}`);
      const result = await authenticate(req);
      expect(result).toEqual({
        authenticated: true,
        message: "Basic Auth Successful",
        status: 200,
        type: 1
      });
    });
  });

  describe("S2s auth", () => {
    let jwksUri: string;
    let jwksServer: Server;

    beforeAll(async (done) => {
      const jwksApp = express();
      jwksApp.use(express.static('test-jwk'));

      const port = await portfinder.getPortPromise({ port: 3000, stopPort: 3333 });
      jwksServer = jwksApp.listen(port, done);
      jwksUri = `http://localhost:${port}/jwks.json`
    });

    afterAll((done) => {
      jwksServer.close(done);
    });

    it("should revoke request with invalid MSAuth1.0 auth", async () => {
      const req = mockRequest("MSAuth1.0 InvalidAuth");
      const result = await authenticate(req, testAud, jwksUri);
      expect(result).toEqual({
        authenticated: false,
        message: "S2S Auth Error: Invalid Bearer Token - missing field",
        status: 403
      });
    });

    it("should accept valid MsAuth1.0 JWT tokens", async () => {
      const signingOpts: SignOptions = {
        keyid: "contrast-test-key",
        algorithm: "RS256",
      };
      const key = fs.readFileSync("./test-jwk/jwtRS256.key");
      const actor = sign({ user: "Jane Doe", aud: testAud }, key, signingOpts);
      const actorToken = `Bearer ${actor}`;

      const access = sign({ }, key, signingOpts);
      const accessToken = `Bearer ${access}`;
      const req = mockRequest(`MSAuth1.0 actortoken=${actorToken},accesstoken=${accessToken},type="PFAT"`);

      const result = await authenticate(req, testAud, jwksUri);
      expect(result).toEqual({
        authenticated: true,
        message: "S2S Auth Successful",
        status: 403, // TODO This should likely be changed to a 200
        type: 2
      });
    });
  });
});
