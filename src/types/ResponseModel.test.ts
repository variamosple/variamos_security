import { describe, expect, it } from "vitest";
import { ResponseModel } from ".";

describe("ResponseModel", () => {
  it("takes the fields given by name", () => {
    const response = new ResponseModel({ errorCode: 401, message: "Log in" });
    expect(response).toMatchObject({ errorCode: 401, message: "Log in" });
    expect(response.data).toBeUndefined();
  });

  it("starts empty and keeps the chained setters", async () => {
    const response = new ResponseModel<string>().withResponse("ok", 1);
    expect(response).toMatchObject({ data: "ok", totalCount: 1 });
    await expect(
      new ResponseModel<string>().withErrorPromise(403, "Denied"),
    ).resolves.toMatchObject({ errorCode: 403, message: "Denied" });
  });
});
