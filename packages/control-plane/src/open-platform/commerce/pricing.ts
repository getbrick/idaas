import {
  commerceCalculationError,
  commerceCommissionInvalid,
  commerceValidationError,
  normalizeCommerceCalculationError,
} from "./errors.js";
import {
  addMoney,
  assertDecimalString,
  assertMoney,
  compareDecimalStrings,
  decimalToUnits,
  multiplyMoneyByBasisPoints,
  multiplyMoneyByDecimal,
  normalizeDecimalString,
  subtractDecimalStrings,
  zeroMoney,
} from "./money.js";
import type {
  CommissionCalculation,
  CommissionRule,
  DecimalString,
  Money,
  Price,
  PriceCalculation,
  PriceCharge,
  PriceTier,
} from "./types.js";

const MONEY_SCALE = 10n ** 18n;

export function calculatePrice(
  tenantId: string,
  price: Price,
  usageByMeter: Readonly<Record<string, DecimalString>>,
): PriceCalculation {
  try {
    const currency = price.currency;
    let charge: PriceCharge;
    let rawTotal: Money;
    let minimumCharge: Money = zeroMoney(currency);
    let chargeMinimum = false;

    switch (price.priceType) {
      case "fixed": {
        const amount = copyMoney(price.fixedAmount);
        rawTotal = amount;
        charge = {
          priceId: price.id,
          priceVersion: price.version,
          priceType: price.priceType,
          quantity: "1",
          includedQuantity: "0",
          billableQuantity: "1",
          unitAmount: amount,
          amount,
          aggregateIds: [],
        };
        break;
      }
      case "perUnit":
      case "mixed": {
        const quantity = normalizeUsage(usageByMeter[price.meterId] ?? "0");
        const includedUnits = normalizeDecimalString(
          assertDecimalString(price.includedUnits, "includedUnits"),
        );
        const fixedAmount = price.priceType === "mixed"
          ? copyMoney(price.fixedAmount)
          : zeroMoney(currency);
        const includedQuantity = minIncludedQuantity(includedUnits, quantity);
        const billable = subtractDecimalStrings(quantity, includedQuantity);
        const usageAmount = multiplyMoneyByDecimal(
          copyMoney(price.unitAmount),
          billable,
          price.roundingMode,
        );
        rawTotal = addMoney(fixedAmount, usageAmount);
        minimumCharge = copyMoney(price.minimumCharge);
        chargeMinimum = compareIntegerMoney(rawTotal, minimumCharge) < 0;
        charge = createUsageCharge(
          price,
          quantity,
          includedQuantity,
          billable,
          copyMoney(price.unitAmount),
          minimumCharge,
          rawTotal,
          chargeMinimum,
        );
        break;
      }
      case "tiered": {
        const quantity = normalizeUsage(usageByMeter[price.meterId] ?? "0");
        const amount = calculateTieredAmount(price, quantity);
        rawTotal = amount;
        charge = {
          priceId: price.id,
          priceVersion: price.version,
          priceType: price.priceType,
          meterId: price.meterId,
          quantity,
          includedQuantity: "0",
          billableQuantity: quantity,
          unitAmount: zeroMoney(currency),
          amount,
          aggregateIds: [],
        };
        break;
      }
    }

    const adjustment = chargeMinimum
      ? subtractMoneyAmount(minimumCharge, rawTotal)
      : zeroMoney(currency);
    return {
      tenantId,
      currency,
      charges: [charge],
      subtotal: rawTotal,
      minimumChargeAdjustment: adjustment,
      total: chargeMinimum ? minimumCharge : rawTotal,
    };
  } catch (error) {
    throw normalizeCommerceCalculationError(error);
  }
}

export function calculateMarketplaceCommission(
  tenantId: string,
  grossAmount: Money,
  rule: CommissionRule,
): CommissionCalculation {
  try {
    const gross = copyMoney(grossAmount);
    if (
      !Number.isSafeInteger(rule.rateBps) ||
      rule.rateBps < 0 ||
      rule.rateBps > 10_000
    ) {
      throw commerceCommissionInvalid("Commission rate is invalid");
    }
    if (
      rule.capBps !== undefined &&
      (!Number.isSafeInteger(rule.capBps) ||
        rule.capBps < 0 ||
        rule.capBps > 10_000)
    ) {
      throw commerceCommissionInvalid("Commission rate cap is invalid");
    }
    const effectiveRateBps = rule.capBps === undefined
      ? rule.rateBps
      : Math.min(rule.rateBps, rule.capBps);
    const uncappedAmount = multiplyMoneyByBasisPoints(
      gross,
      effectiveRateBps,
      "halfUp",
    );
    const commissionAmount = rule.capAmount === undefined
      ? uncappedAmount
      : minMoney(uncappedAmount, copyMoney(rule.capAmount));
    return {
      tenantId,
      partnerAccountId: rule.partnerAccountId,
      listingId: rule.listingId,
      ruleId: rule.id,
      grossAmount: gross,
      rateBps: effectiveRateBps,
      uncappedAmount,
      commissionAmount,
      partnerAmount: {
        amountMinor: gross.amountMinor - commissionAmount.amountMinor,
        currency: gross.currency,
      },
      capped: commissionAmount.amountMinor !== uncappedAmount.amountMinor,
    };
  } catch (error) {
    throw normalizeCommerceCalculationError(error);
  }
}

function createUsageCharge(
  price: Price & { priceType: "perUnit" | "mixed" },
  quantity: DecimalString,
  includedQuantity: DecimalString,
  billableQuantity: DecimalString,
  unitAmount: Money,
  minimumCharge: Money,
  rawTotal: Money,
  chargeMinimum: boolean,
): PriceCharge {
  return {
    priceId: price.id,
    priceVersion: price.version,
    priceType: price.priceType,
    meterId: price.meterId,
    quantity,
    includedQuantity,
    billableQuantity,
    unitAmount,
    amount: chargeMinimum ? minimumCharge : rawTotal,
    aggregateIds: [],
  };
}

function calculateTieredAmount(price: Price & { priceType: "tiered" }, quantity: DecimalString): Money {
  const tiers = validateTiers(price.tiers, price.currency);
  let lower = "0";
  let numerator = 0n;
  for (const tier of tiers) {
    let upper = tier.upTo ?? quantity;
    if (compareDecimalStrings(upper, quantity) > 0) upper = quantity;
    if (compareDecimalStrings(upper, lower) <= 0) {
      lower = upper;
      continue;
    }
    const segment = subtractDecimalStrings(upper, lower);
    numerator += decimalToUnits(segment) * BigInt(tier.unitAmount.amountMinor);
    lower = upper;
    if (compareDecimalStrings(lower, quantity) >= 0) break;
  }
  const amount = roundNonNegativeRatio(numerator, MONEY_SCALE, price.roundingMode);
  if (amount > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw commerceCalculationError();
  }
  return { amountMinor: Number(amount), currency: price.currency };
}

function validateTiers(
  tiers: readonly PriceTier[],
  currency: Money["currency"],
): readonly PriceTier[] {
  if (!Array.isArray(tiers) || tiers.length === 0) {
    throw commerceValidationError("Tiered price requires at least one tier", "tiers");
  }
  let previous = "0";
  let unlimitedSeen = false;
  const normalized = tiers.map((tier, index) => {
    if (unlimitedSeen) {
      throw commerceValidationError("Unlimited tier must be last", "tiers");
    }
    const upTo = tier.upTo === null
      ? null
      : normalizeDecimalString(
        assertDecimalString(tier.upTo, `tiers.${index}.upTo`),
      );
    if (upTo !== null) {
      if (compareDecimalStrings(upTo, previous) <= 0) {
        throw commerceValidationError("Tier limits must increase", "tiers");
      }
      previous = upTo;
    } else {
      unlimitedSeen = true;
    }
    const amount = copyMoney(tier.unitAmount);
    if (amount.currency !== currency) {
      throw commerceValidationError("Tier currency is invalid", "tiers");
    }
    return { upTo, unitAmount: amount };
  });
  if (!unlimitedSeen) {
    throw commerceValidationError("Tiered price requires an unlimited tier", "tiers");
  }
  return normalized;
}

function roundNonNegativeRatio(
  numerator: bigint,
  denominator: bigint,
  mode: Price["roundingMode"],
): bigint {
  const quotient = numerator / denominator;
  const remainder = numerator % denominator;
  if (remainder === 0n) return quotient;
  const comparison = remainder * 2n - denominator;
  if (mode === "halfUp") return comparison >= 0n ? quotient + 1n : quotient;
  if (comparison > 0n) return quotient + 1n;
  if (comparison < 0n) return quotient;
  return quotient % 2n === 0n ? quotient : quotient + 1n;
}

function normalizeUsage(value: DecimalString): DecimalString {
  return normalizeDecimalString(assertDecimalString(value, "usage", true));
}

function minIncludedQuantity(
  includedUnits: DecimalString,
  quantity: DecimalString,
): DecimalString {
  return compareDecimalStrings(includedUnits, quantity) > 0
    ? quantity
    : includedUnits;
}

function copyMoney(value: Money): Money {
  const normalized = assertMoney(value, "amount");
  return { amountMinor: normalized.amountMinor, currency: normalized.currency };
}

function compareIntegerMoney(left: Money, right: Money): number {
  if (left.currency !== right.currency) {
    throw commerceValidationError("Money currencies must match", "currency");
  }
  return left.amountMinor === right.amountMinor
    ? 0
    : left.amountMinor < right.amountMinor
    ? -1
    : 1;
}

function subtractMoneyAmount(left: Money, right: Money): Money {
  if (left.currency !== right.currency) {
    throw commerceValidationError("Money currencies must match", "currency");
  }
  if (left.amountMinor < right.amountMinor) {
    throw commerceValidationError("Minimum charge is lower than raw total", "minimumCharge");
  }
  return { amountMinor: left.amountMinor - right.amountMinor, currency: left.currency };
}

function minMoney(left: Money, right: Money): Money {
  return compareIntegerMoney(left, right) <= 0 ? left : right;
}
