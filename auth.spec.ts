import { Request } from "express";
import { authenticate } from "./auth";

function mockRequest(authorizationHeader?: string): Request {
  return {
    headers: {
      authorization: authorizationHeader,
    }
  } as any as Request;
}

describe("auth.ts", () => {

  beforeEach(() => {
    process.env.AUDIENCE = "test-aud";
  });

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

  it("should revoke request with invalid basic auth", async () => {
    const req = mockRequest("Basic InvalidBasicAuth");
    const result = await authenticate(req);
    expect(result).toEqual({
      authenticated: false, 
      message: "Basic Auth Error", 
      status: 403
    });
  });

  it("should revoke request with invalid MSAuth1.0 auth", async () => {
    const req = mockRequest("MSAuth1.0 InvalidAuth");
    const result = await authenticate(req);
    expect(result).toEqual({
      authenticated: false, 
      message: "S2S Auth Error: Invalid Bearer Token - missing field", 
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
  })
});
