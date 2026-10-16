import { describe, expect, it } from "vitest";
import {
  calculateCvss,
  cvssRoundUp,
  fallbackCvssForSeverity,
  parseCvss,
  scoreToSeverity,
} from "../src/cvss.js";

describe("CVSS v3.1 deterministic scoring", () => {
  it("computes official FIRST CVSS v3.1 reference base scores accurately", () => {
    // 1. Critical RCE (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) => 9.8 Critical
    const rce = parseCvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    expect(rce).not.toBeNull();
    expect(rce?.score).toBe(9.8);
    expect(rce?.severity).toBe("critical");

    // 2. Scope Changed Critical (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H) => 10.0 Critical
    const scopeChanged = parseCvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
    expect(scopeChanged?.score).toBe(10.0);
    expect(scopeChanged?.severity).toBe("critical");

    // 3. High Unauthenticated File Read (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N) => 7.5 High
    const fileRead = parseCvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
    expect(fileRead?.score).toBe(7.5);
    expect(fileRead?.severity).toBe("high");

    // 4. Medium Stored XSS / UI Required (AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N) => 5.4 Medium
    const xss = parseCvss("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
    expect(xss?.score).toBe(5.4);
    expect(xss?.severity).toBe("medium");

    // 5. Medium Complex UI Required (AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N) => 6.8 Medium
    const h1Style = parseCvss("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N");
    expect(h1Style?.score).toBe(6.8);
    expect(h1Style?.severity).toBe("medium");

    // 6. Low Local Info Leak (AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N) => 2.5 Low
    const lowLocal = parseCvss("CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N");
    expect(lowLocal?.score).toBe(2.5);
    expect(lowLocal?.severity).toBe("low");
  });

  it("parses loose metric objects and rejects all-zero impact vectors", () => {
    const parsed = parseCvss({
      av: "n",
      ac: "l",
      pr: "l",
      ui: "n",
      s: "u",
      c: "h",
      i: "h",
      a: "n",
    });
    expect(parsed).not.toBeNull();
    expect(parsed?.vector).toBe("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
    expect(parsed?.score).toBe(8.1);
    expect(parsed?.severity).toBe("high");

    // All-none impact should return null so caller falls back to baseline severity
    expect(parseCvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")).toBeNull();
  });

  it("provides deterministic fallbacks for every severity bucket", () => {
    expect(fallbackCvssForSeverity("critical").severity).toBe("critical");
    expect(fallbackCvssForSeverity("high").severity).toBe("high");
    expect(fallbackCvssForSeverity("medium").severity).toBe("medium");
    expect(fallbackCvssForSeverity("low").severity).toBe("low");
    expect(cvssRoundUp(4.0)).toBe(4.0);
    expect(cvssRoundUp(4.02)).toBe(4.1);
    expect(scoreToSeverity(9.0)).toBe("critical");
    expect(scoreToSeverity(7.0)).toBe("high");
    expect(scoreToSeverity(4.0)).toBe("medium");
    expect(scoreToSeverity(3.9)).toBe("low");
    expect(
      calculateCvss({ AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "N", I: "N", A: "N" }).score,
    ).toBe(0.0);
  });
});
