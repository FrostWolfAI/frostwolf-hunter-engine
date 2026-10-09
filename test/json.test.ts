import { describe, expect, it } from "vitest";
import { parseLooseJson } from "../src/json.js";

describe("parseLooseJson", () => {
  it("parses a clean object", () => {
    expect(parseLooseJson('{"a":1}')).toEqual({ a: 1 });
  });
  it("recovers a double-escaped body (the quantised-model case)", () => {
    expect(parseLooseJson('{\\"verdict\\":\\"success\\",\\"n\\":1}')).toEqual({
      verdict: "success",
      n: 1,
    });
  });
  it("strips a ```json fence", () => {
    expect(parseLooseJson('```json\n{"a":2}\n```')).toEqual({ a: 2 });
  });
  it("extracts an object embedded in prose", () => {
    expect(parseLooseJson('Sure, here: {"a":3} — done.')).toEqual({ a: 3 });
  });
  it("ignores braces inside strings when extracting", () => {
    expect(parseLooseJson('noise {"msg":"a } b"} tail')).toEqual({ msg: "a } b" });
  });
  it("returns null when there is no JSON", () => {
    expect(parseLooseJson("no json here")).toBeNull();
  });
});
