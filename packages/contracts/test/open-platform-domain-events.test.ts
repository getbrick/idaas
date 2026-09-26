import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  OPEN_PLATFORM_DOMAIN_EVENT_ACTIONS,
  OPEN_PLATFORM_DOMAIN_EVENT_CATALOG,
  OPEN_PLATFORM_DOMAIN_EVENT_RESOURCES,
  OPEN_PLATFORM_DOMAIN_EVENTS,
  OPEN_PLATFORM_WEBHOOK_EVENTS,
  isOpenPlatformDomainEventName,
  openPlatformDomainEventNameParts,
  type OpenPlatformDomainEvent,
} from "../src/open-platform.js";

const CORE_RESOURCES = [
  "tenant",
  "developer_organization",
  "application",
  "client",
  "credential",
  "api_product",
  "api_version",
  "subscription",
  "scope_grant",
  "usage",
] as const;

const COMMERCE_COMPLIANCE_CATALOG: Readonly<Record<string, readonly string[]>> = {
  commerce_listing: ["created", "updated", "status_changed", "deprecated"],
  commerce_partner: ["created", "updated", "status_changed"],
  commerce_commission: ["created", "updated", "status_changed"],
  commerce_account: ["created", "updated", "status_changed"],
  commerce_invoice: ["created", "updated", "status_changed"],
  commerce_dispute: ["created", "updated", "status_changed", "decided"],
  compliance_data_asset: ["created", "updated", "status_changed"],
  compliance_consent_record: ["created", "status_changed", "granted", "withdrawn"],
  compliance_privacy_request: ["created", "status_changed", "verified", "decided"],
  compliance_retention_policy: ["created", "status_changed", "executed"],
  compliance_cross_border_assessment: ["created", "status_changed", "decided"],
  compliance_vendor: ["created", "updated", "status_changed"],
};

const COMMERCE_COMPLIANCE_EVENTS: readonly OpenPlatformDomainEvent[] = [
  "commerce_listing.created",
  "commerce_listing.updated",
  "commerce_listing.status_changed",
  "commerce_listing.deprecated",
  "commerce_partner.created",
  "commerce_partner.updated",
  "commerce_partner.status_changed",
  "commerce_commission.created",
  "commerce_commission.updated",
  "commerce_commission.status_changed",
  "commerce_account.created",
  "commerce_account.updated",
  "commerce_account.status_changed",
  "commerce_invoice.created",
  "commerce_invoice.updated",
  "commerce_invoice.status_changed",
  "commerce_dispute.created",
  "commerce_dispute.updated",
  "commerce_dispute.status_changed",
  "commerce_dispute.decided",
  "compliance_data_asset.created",
  "compliance_data_asset.updated",
  "compliance_data_asset.status_changed",
  "compliance_consent_record.created",
  "compliance_consent_record.status_changed",
  "compliance_consent_record.granted",
  "compliance_consent_record.withdrawn",
  "compliance_privacy_request.created",
  "compliance_privacy_request.status_changed",
  "compliance_privacy_request.verified",
  "compliance_privacy_request.decided",
  "compliance_retention_policy.created",
  "compliance_retention_policy.status_changed",
  "compliance_retention_policy.executed",
  "compliance_cross_border_assessment.created",
  "compliance_cross_border_assessment.status_changed",
  "compliance_cross_border_assessment.decided",
  "compliance_vendor.created",
  "compliance_vendor.updated",
  "compliance_vendor.status_changed",
];

const CORE_EVENT_COUNT = 32;

describe("open platform commerce and compliance domain event catalog", () => {
  it("keeps core resources first and appends every commerce and compliance resource", () => {
    assert.deepEqual(
      OPEN_PLATFORM_DOMAIN_EVENT_RESOURCES.slice(0, CORE_RESOURCES.length),
      [...CORE_RESOURCES],
    );
    assert.deepEqual(OPEN_PLATFORM_DOMAIN_EVENT_RESOURCES.slice(CORE_RESOURCES.length), [
      ...Object.keys(COMMERCE_COMPLIANCE_CATALOG),
    ]);
    for (const resource of Object.keys(COMMERCE_COMPLIANCE_CATALOG)) {
      assert.ok((OPEN_PLATFORM_DOMAIN_EVENT_RESOURCES as readonly string[]).includes(resource), resource);
      assert.deepEqual(
        OPEN_PLATFORM_DOMAIN_EVENT_CATALOG[resource as keyof typeof OPEN_PLATFORM_DOMAIN_EVENT_CATALOG],
        COMMERCE_COMPLIANCE_CATALOG[resource],
      );
    }
  });

  it("keeps every commerce and compliance event name in the derived catalog", () => {
    for (const event of COMMERCE_COMPLIANCE_EVENTS) {
      assert.ok(isOpenPlatformDomainEventName(event), event);
      assert.ok((OPEN_PLATFORM_WEBHOOK_EVENTS as readonly string[]).includes(event), event);
      assert.deepEqual(openPlatformDomainEventNameParts(event), {
        resource: event.slice(0, event.indexOf(".")),
        action: event.slice(event.indexOf(".") + 1),
      });
    }
  });

  it("stays backward compatible with previously published core event names", () => {
    for (const event of [
      "tenant.created",
      "tenant.updated",
      "tenant.status_changed",
      "developer_organization.created",
      "application.created",
      "application.updated",
      "application.status_changed",
      "client.created",
      "client.updated",
      "client.status_changed",
      "credential.created",
      "credential.status_changed",
      "api_product.created",
      "api_product.published",
      "api_product.deprecated",
      "api_product.status_changed",
      "api_version.created",
      "api_version.published",
      "api_version.deprecated",
      "api_version.status_changed",
      "subscription.created",
      "subscription.status_changed",
      "scope_grant.created",
      "scope_grant.status_changed",
      "usage.threshold_reached",
    ] as readonly OpenPlatformDomainEvent[]) {
      assert.ok(isOpenPlatformDomainEventName(event), event);
    }
    assert.deepEqual(
      [...OPEN_PLATFORM_WEBHOOK_EVENTS.slice(0, CORE_EVENT_COUNT)],
      CORE_RESOURCES.flatMap((resource) =>
        OPEN_PLATFORM_DOMAIN_EVENT_CATALOG[resource].map((action) => `${resource}.${action}`),
      ),
    );
  });

  it("derives a duplicate free event list of the expected size", () => {
    assert.equal(OPEN_PLATFORM_DOMAIN_EVENTS.length, CORE_EVENT_COUNT + COMMERCE_COMPLIANCE_EVENTS.length);
    assert.equal(OPEN_PLATFORM_DOMAIN_EVENTS.length, 72);
    assert.equal(OPEN_PLATFORM_WEBHOOK_EVENTS.length, OPEN_PLATFORM_DOMAIN_EVENTS.length);
    assert.equal(
      new Set(OPEN_PLATFORM_DOMAIN_EVENTS).size,
      OPEN_PLATFORM_DOMAIN_EVENTS.length,
    );
    const flattened = OPEN_PLATFORM_DOMAIN_EVENT_RESOURCES.flatMap((resource) =>
      OPEN_PLATFORM_DOMAIN_EVENT_CATALOG[resource].map((action) => `${resource}.${action}`),
    );
    assert.deepEqual([...OPEN_PLATFORM_DOMAIN_EVENTS], flattened);
    assert.ok(Object.isFrozen(OPEN_PLATFORM_DOMAIN_EVENTS));
    assert.ok(Object.isFrozen(OPEN_PLATFORM_DOMAIN_EVENT_RESOURCES));
  });

  it("accepts the new names and rejects unknown commerce resources", () => {
    assert.equal(isOpenPlatformDomainEventName("commerce_invoice.status_changed"), true);
    assert.equal(isOpenPlatformDomainEventName("compliance_privacy_request.decided"), true);
    assert.equal(isOpenPlatformDomainEventName("compliance_retention_policy.executed"), true);
    assert.equal(isOpenPlatformDomainEventName("commerce_unknown.created"), false);
    assert.equal(isOpenPlatformDomainEventName("commerce_invoice.deleted"), false);
  });

  it("keeps every catalog action registered in the shared action list", () => {
    for (const action of [
      "granted",
      "withdrawn",
      "decided",
      "executed",
      "verified",
    ] as const) {
      assert.ok((OPEN_PLATFORM_DOMAIN_EVENT_ACTIONS as readonly string[]).includes(action), action);
    }
    for (const resource of OPEN_PLATFORM_DOMAIN_EVENT_RESOURCES) {
      assert.ok(OPEN_PLATFORM_DOMAIN_EVENT_CATALOG[resource].length > 0, resource);
      for (const action of OPEN_PLATFORM_DOMAIN_EVENT_CATALOG[resource]) {
        assert.ok(
          (OPEN_PLATFORM_DOMAIN_EVENT_ACTIONS as readonly string[]).includes(action),
          `${resource}.${action}`,
        );
      }
    }
    assert.equal(
      new Set(OPEN_PLATFORM_DOMAIN_EVENT_ACTIONS).size,
      OPEN_PLATFORM_DOMAIN_EVENT_ACTIONS.length,
    );
  });
});
