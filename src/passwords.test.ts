import { describe, expect, it } from "vitest";
import { newPassword } from "./passwords.js";

describe("newPassword", () => {
  it("is long, mixed, and free of look-alikes", () => {
    for (let n = 0; n < 50; n++) {
      const p = newPassword();
      expect(p).toHaveLength(24);
      expect(p).toMatch(/[a-z]/);
      expect(p).toMatch(/[A-Z]/);
      expect(p).toMatch(/[0-9]/);
      expect(p).toMatch(/[!@#$%^&*\-_=+]/);
      expect(p).not.toMatch(/[lIO01]/);
    }
    expect(newPassword()).not.toBe(newPassword());
  });
});
