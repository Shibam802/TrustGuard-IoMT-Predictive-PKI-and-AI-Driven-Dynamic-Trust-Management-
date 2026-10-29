const { expect } = require("chai");
const { ethers } = require("hardhat");
const { anyValue } = require("@nomicfoundation/hardhat-chai-matchers/withArgs");

describe("TrustGuardLedger", function () {
  let ledger, owner, otherWriter, stranger;

  const EventType = { ISSUE: 0, ROTATE: 1, REVOKE: 2, ESCALATE: 3 };

  beforeEach(async function () {
    [owner, otherWriter, stranger] = await ethers.getSigners();
    const Ledger = await ethers.getContractFactory("TrustGuardLedger");
    ledger = await Ledger.deploy();
    await ledger.waitForDeployment();
  });

  it("deploys with the deployer as an authorized writer", async function () {
    expect(await ledger.authorizedWriters(owner.address)).to.equal(true);
  });

  it("records an ISSUE event and increments entryCount", async function () {
    await ledger.recordEvent(EventType.ISSUE, "device_01", "cert_abc123", "Initial enrollment");
    expect(await ledger.entryCount()).to.equal(1);

    const entry = await ledger.getEntry(0);
    expect(entry.deviceId).to.equal("device_01");
    expect(entry.certId).to.equal("cert_abc123");
    expect(entry.eventType).to.equal(EventType.ISSUE);
  });

  it("emits an EntryRecorded event with the correct fields", async function () {
    await expect(
      ledger.recordEvent(EventType.ROTATE, "device_02", "cert_def456", "Predictive rotation")
    )
      .to.emit(ledger, "EntryRecorded")
      .withArgs(0, EventType.ROTATE, "device_02", "cert_def456", "Predictive rotation", anyValue, owner.address);
  });

  it("rejects recordEvent from an unauthorized address", async function () {
    await expect(
      ledger.connect(stranger).recordEvent(EventType.REVOKE, "device_03", "cert_ghi789", "Confirmed breach")
    ).to.be.revertedWith("TrustGuardLedger: caller is not an authorized CA writer");
  });

  it("allows the owner to authorize a new writer, who can then record events", async function () {
    await ledger.authorizeWriter(otherWriter.address);
    expect(await ledger.authorizedWriters(otherWriter.address)).to.equal(true);

    await ledger.connect(otherWriter).recordEvent(
      EventType.ISSUE, "device_04", "cert_jkl012", "Enrolled by backup CA node"
    );
    expect(await ledger.entryCount()).to.equal(1);
  });

  it("allows the owner to revoke a writer's access", async function () {
    await ledger.authorizeWriter(otherWriter.address);
    await ledger.revokeWriter(otherWriter.address);
    expect(await ledger.authorizedWriters(otherWriter.address)).to.equal(false);

    await expect(
      ledger.connect(otherWriter).recordEvent(EventType.ISSUE, "device_05", "cert_x", "should fail")
    ).to.be.revertedWith("TrustGuardLedger: caller is not an authorized CA writer");
  });

  it("prevents a non-owner from authorizing writers", async function () {
    await expect(
      ledger.connect(stranger).authorizeWriter(stranger.address)
    ).to.be.revertedWithCustomError(ledger, "OwnableUnauthorizedAccount");
  });

  it("reverts when fetching an out-of-range index", async function () {
    await expect(ledger.getEntry(0)).to.be.revertedWith("TrustGuardLedger: index out of range");
  });

  it("filters entries correctly by device via getEntriesForDevice", async function () {
    await ledger.recordEvent(EventType.ISSUE, "device_A", "cert_1", "issue A");
    await ledger.recordEvent(EventType.ISSUE, "device_B", "cert_2", "issue B");
    await ledger.recordEvent(EventType.ROTATE, "device_A", "cert_3", "rotate A");

    const entriesForA = await ledger.getEntriesForDevice("device_A");
    expect(entriesForA.length).to.equal(2);
    expect(entriesForA[0].certId).to.equal("cert_1");
    expect(entriesForA[1].certId).to.equal("cert_3");
  });

  it("records a full ISSUE -> ROTATE -> REVOKE lifecycle in order", async function () {
    await ledger.recordEvent(EventType.ISSUE, "device_09", "cert_a", "enrolled");
    await ledger.recordEvent(EventType.ROTATE, "device_09", "cert_b", "predictive rotation");
    await ledger.recordEvent(EventType.REVOKE, "device_09", "cert_b", "confirmed breach");

    expect(await ledger.entryCount()).to.equal(3);
    const history = await ledger.getEntriesForDevice("device_09");
    expect(history.map((e) => Number(e.eventType))).to.deep.equal([
      EventType.ISSUE, EventType.ROTATE, EventType.REVOKE,
    ]);
  });
});
