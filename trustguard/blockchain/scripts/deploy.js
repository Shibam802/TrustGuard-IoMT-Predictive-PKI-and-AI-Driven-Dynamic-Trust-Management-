const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
  const [deployer] = await hre.ethers.getSigners();
  console.log("Deploying TrustGuardLedger with account:", deployer.address);

  const balance = await hre.ethers.provider.getBalance(deployer.address);
  console.log("Deployer balance:", hre.ethers.formatEther(balance), "ETH");

  const NAME = process.env.CONTRACT || "TrustGuardLedger";   // or "TrustGuardLedgerCompact"
  const Ledger = await hre.ethers.getContractFactory(NAME);
  const ledger = await Ledger.deploy();
  await ledger.waitForDeployment();

  const address = await ledger.getAddress();
  console.log(NAME + " deployed to:", address);

  // Write deployment info (address + ABI) for the Python client to consume.
  const artifact = await hre.artifacts.readArtifact(NAME);
  const deploymentInfo = {
    address,
    abi: artifact.abi,
    deployer: deployer.address,
    network: hre.network.name,
    deployedAt: new Date().toISOString(),
  };

  const outPath = path.join(__dirname, "..", "python_client", NAME === "TrustGuardLedger" ? "deployment.json" : "deployment_compact.json");
  fs.writeFileSync(outPath, JSON.stringify(deploymentInfo, null, 2));
  console.log("Deployment info written to:", outPath);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
