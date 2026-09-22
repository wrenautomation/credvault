/** Passwords drawn here: nobody picks them, nobody sees them. */
import { randomInt } from "node:crypto";

const LOWER = "abcdefghijkmnopqrstuvwxyz";
const UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ";
const DIGIT = "23456789";
const SYMBOL = "!@#$%^&*-_=+";
const ALL = LOWER + UPPER + DIGIT + SYMBOL;

/** A password no site refuses: 24 chars, at least one of each class, no look-alikes (l/1/O/0). */
export function newPassword(length = 24, pick: (n: number) => number = randomInt): string {
  const chars = [LOWER, UPPER, DIGIT, SYMBOL].map((set) => set[pick(set.length)] ?? "a");
  while (chars.length < length) chars.push(ALL[pick(ALL.length)] ?? "a");
  for (let i = chars.length - 1; i > 0; i--) {
    const j = pick(i + 1);
    [chars[i], chars[j]] = [chars[j] as string, chars[i] as string];
  }
  return chars.join("");
}
