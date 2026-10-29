const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("TrustGuardLedgerCompact", function () {
  let c, owner, stranger;
  beforeEach(async () => {
    [owner, stranger] = await ethers.getSigners();
    c = await (await ethers.getContractFactory("TrustGuardLedgerCompact")).deploy();
    await c.waitForDeployment();
  });
  it("stores hashes and verifies matching strings", async () => {
    await c.recordEvent(0, "device_01", "cert_a", "enrolled");
    expect(await c.entryCount()).to.equal(1);
    expect(await c.verifyEntry(0, "device_01", "cert_a", "enrolled")).to.equal(true);
  });
  it("detects a different detail string", async () => {
    await c.recordEvent(2, "device_01", "cert_a", "confirmed breach");
    expect(await c.verifyEntry(0, "device_01", "cert_a", "tampered")).to.equal(false);
  });
  it("emits the full strings in the event log", async () => {
    await expect(c.recordEvent(1, "d", "c", "why")).to.emit(c, "EntryRecorded").withArgs(0, 1, "d", "c", "why");
  });
  it("rejects unauthorised writers", async () => {
    await expect(c.connect(stranger).recordEvent(0, "d", "c", "x")).to.be.revertedWith("TrustGuardLedger: caller is not an authorized CA writer");
  });
});
