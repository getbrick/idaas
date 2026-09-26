import {
  commerceInvalidTotal,
  commerceNegativeAmount,
  commerceValidationError,
} from "./errors.js";
import {
  COMMERCE_CURRENCIES,
  type CommerceCurrency,
  type DecimalString,
  type Money,
  type RoundingMode,
} from "./types.js";

const DECIMAL_PATTERN = /^(?:0|[1-9][0-9]*)(?:\.[0-9]{1,18})?$/u;
const MAX_DECIMAL_DIGITS = 128;
const DECIMAL_SCALE = 18n;
const MAX_MINOR_UNITS = BigInt(Number.MAX_SAFE_INTEGER);

export function isDecimalString(value: unknown): value is DecimalString {
  return typeof value === "string" &&
    value.length <= MAX_DECIMAL_DIGITS &&
    DECIMAL_PATTERN.test(value);
}

export function assertDecimalString(
  value: unknown,
  field = "quantity",
  allowZero = true,
): DecimalString {
  if (!isDecimalString(value)) {
    throw commerceValidationError("Decimal string is invalid", field);
  }
  const normalized = normalizeDecimalString(value);
  if (!allowZero && normalized === "0") {
    throw commerceValidationError("Decimal string must be positive", field);
  }
  return normalized;
}

export function normalizeDecimalString(value: DecimalString): DecimalString {
  const [integerPart, fractionPart = ""] = value.split(".");
  const trimmedFraction = fractionPart.replace(/0+$/u, "");
  const trimmedInteger = integerPart.replace(/^0+(?=[0-9])/u, "");
  return trimmedFraction.length === 0
    ? trimmedInteger
    : `${trimmedInteger}.${trimmedFraction}`;
}

export function compareDecimalStrings(
  left: DecimalString,
  right: DecimalString,
): number {
  const normalizedLeft = assertDecimalString(left);
  const normalizedRight = assertDecimalString(right);
  const leftParts = decimalParts(normalizedLeft);
  const rightParts = decimalParts(normalizedRight);
  if (leftParts.integer !== rightParts.integer) {
    return leftParts.integer < rightParts.integer ? -1 : 1;
  }
  if (leftParts.fraction === rightParts.fraction) return 0;
  return leftParts.fraction < rightParts.fraction ? -1 : 1;
}

export function addDecimalStrings(
  left: DecimalString,
  right: DecimalString,
): DecimalString {
  const result = decimalToUnits(assertDecimalString(left)) +
    decimalToUnits(assertDecimalString(right));
  return decimalFromUnits(result);
}

export function subtractDecimalStrings(
  left: DecimalString,
  right: DecimalString,
): DecimalString {
  const leftUnits = decimalToUnits(assertDecimalString(left));
  const rightUnits = decimalToUnits(assertDecimalString(right));
  if (rightUnits > leftUnits) throw commerceNegativeAmount();
  return decimalFromUnits(leftUnits - rightUnits);
}

export function maxDecimalStrings(
  left: DecimalString,
  right: DecimalString,
): DecimalString {
  return compareDecimalStrings(left, right) >= 0 ? left : right;
}

export function minDecimalStrings(
  left: DecimalString,
  right: DecimalString,
): DecimalString {
  return compareDecimalStrings(left, right) <= 0 ? left : right;
}

export function isZeroDecimalString(value: DecimalString): boolean {
  return assertDecimalString(value) === "0";
}

export function assertMoney(
  value: unknown,
  field = "amount",
  allowZero = true,
): Money {
  if (
    value === null ||
    typeof value !== "object" ||
    !Number.isSafeInteger((value as Money).amountMinor) ||
    (value as Money).amountMinor < 0 ||
    (!allowZero && (value as Money).amountMinor === 0) ||
    !isCommerceCurrency((value as Money).currency)
  ) {
    throw commerceNegativeAmount(
      allowZero
        ? "Money must use a non-negative integer minor-unit amount"
        : "Money must use a positive integer minor-unit amount",
    );
  }
  return {
    amountMinor: (value as Money).amountMinor,
    currency: (value as Money).currency,
  };
}

export function isCommerceCurrency(value: unknown): value is CommerceCurrency {
  return (
    typeof value === "string" &&
    (COMMERCE_CURRENCIES as readonly string[]).includes(value)
  );
}

export function zeroMoney(currency: CommerceCurrency = "CNY"): Money {
  return { amountMinor: 0, currency };
}

export function addMoney(left: Money, right: Money): Money {
  const normalizedLeft = assertMoney(left);
  const normalizedRight = assertMoney(right);
  assertSameCurrency(normalizedLeft, normalizedRight);
  return checkedMoney(
    BigInt(normalizedLeft.amountMinor) + BigInt(normalizedRight.amountMinor),
    normalizedLeft.currency,
  );
}

export function subtractMoney(left: Money, right: Money): Money {
  const normalizedLeft = assertMoney(left);
  const normalizedRight = assertMoney(right);
  assertSameCurrency(normalizedLeft, normalizedRight);
  const difference = BigInt(normalizedLeft.amountMinor) -
    BigInt(normalizedRight.amountMinor);
  if (difference < 0n) {
    throw commerceInvalidTotal("Money subtotal would become negative");
  }
  return checkedMoney(difference, normalizedLeft.currency);
}

export function sumMoney(
  values: readonly Money[],
  currency: CommerceCurrency = "CNY",
): Money {
  return values.reduce<Money>(
    (total, value) => addMoney(total, assertMoney(value, "amount")),
    zeroMoney(currency),
  );
}

export function multiplyMoneyByDecimal(
  amount: Money,
  quantity: DecimalString,
  roundingMode: RoundingMode,
): Money {
  const normalizedAmount = assertMoney(amount, "unitAmount");
  const normalizedQuantity = assertDecimalString(quantity);
  const parts = decimalParts(normalizedQuantity);
  const result = roundRatio(
    BigInt(normalizedAmount.amountMinor) * parts.units,
    10n ** DECIMAL_SCALE,
    roundingMode,
  );
  return checkedMoney(result, normalizedAmount.currency);
}

export function multiplyMoneyByBasisPoints(
  amount: Money,
  basisPoints: number,
  roundingMode: RoundingMode = "halfUp",
): Money {
  const normalizedAmount = assertMoney(amount);
  assertBasisPoints(basisPoints, "basisPoints");
  return checkedMoney(
    roundRatio(
      BigInt(normalizedAmount.amountMinor) * BigInt(basisPoints),
      10_000n,
      roundingMode,
    ),
    normalizedAmount.currency,
  );
}

export function extractInclusiveTax(
  grossAmount: Money,
  taxRateBps: number,
): Money {
  const normalizedAmount = assertMoney(grossAmount);
  assertBasisPoints(taxRateBps, "taxRateBps");
  return checkedMoney(
    roundRatio(
      BigInt(normalizedAmount.amountMinor) * BigInt(taxRateBps),
      10_000n + BigInt(taxRateBps),
      "halfUp",
    ),
    normalizedAmount.currency,
  );
}

export function formatMoneyAsDecimalString(amount: Money): DecimalString {
  const normalized = assertMoney(amount);
  const units = BigInt(normalized.amountMinor);
  const whole = units / 100n;
  const fraction = (units % 100n).toString().padStart(2, "0");
  return fraction === "00" ? whole.toString() : `${whole.toString()}.${fraction}`;
}

export function addIntegerMinor(
  amountMinor: number,
  deltaMinor: number,
): number {
  if (
    !Number.isSafeInteger(amountMinor) ||
    !Number.isSafeInteger(deltaMinor) ||
    amountMinor < 0
  ) {
    throw commerceValidationError("Minor-unit integer is invalid");
  }
  return checkedMinor(BigInt(amountMinor) + BigInt(deltaMinor));
}

function decimalParts(value: DecimalString): {
  integer: bigint;
  fraction: bigint;
  units: bigint;
} {
  const [integerPart, fractionPart = ""] = value.split(".");
  const integer = BigInt(integerPart);
  const fractionText = fractionPart.padEnd(18, "0");
  const fraction = fractionText.length === 0
    ? 0n
    : BigInt(fractionText);
  return {
    integer,
    fraction,
    units: integer * 10n ** DECIMAL_SCALE + fraction,
  };
}

export function decimalToUnits(value: DecimalString): bigint {
  return decimalParts(assertDecimalString(value)).units;
}

function decimalFromUnits(units: bigint): DecimalString {
  if (units < 0n) throw commerceNegativeAmount();
  const whole = units / 10n ** DECIMAL_SCALE;
  const fraction = (units % 10n ** DECIMAL_SCALE)
    .toString()
    .padStart(18, "0")
    .replace(/0+$/u, "");
  return fraction.length === 0
    ? whole.toString()
    : `${whole.toString()}.${fraction}`;
}

function roundRatio(
  numerator: bigint,
  denominator: bigint,
  roundingMode: RoundingMode,
): bigint {
  if (numerator < 0n || denominator <= 0n) throw commerceNegativeAmount();
  const quotient = numerator / denominator;
  const remainder = numerator % denominator;
  if (remainder === 0n) return quotient;
  const comparison = remainder * 2n - denominator;
  if (roundingMode === "halfUp") {
    return comparison >= 0n ? quotient + 1n : quotient;
  }
  if (comparison > 0n) return quotient + 1n;
  if (comparison < 0n) return quotient;
  return quotient % 2n === 0n ? quotient : quotient + 1n;
}

function checkedMoney(
  amountMinor: bigint,
  currency: CommerceCurrency,
): Money {
  return { amountMinor: checkedMinor(amountMinor), currency };
}

function checkedMinor(amountMinor: bigint): number {
  if (amountMinor < 0n || amountMinor > MAX_MINOR_UNITS) {
    throw commerceInvalidTotal("Money amount exceeds the supported range");
  }
  return Number(amountMinor);
}

function assertSameCurrency(left: Money, right: Money): void {
  if (left.currency !== right.currency) {
    throw commerceValidationError("Money currencies must match", "currency");
  }
}

function assertBasisPoints(value: number, field: string): void {
  if (!Number.isSafeInteger(value) || value < 0 || value > 10_000) {
    throw commerceValidationError("Basis points are invalid", field);
  }
}
