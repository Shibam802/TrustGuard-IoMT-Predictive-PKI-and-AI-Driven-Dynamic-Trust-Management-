/**
 * manual_compile.js -- Compiles TrustGuardLedger.sol using the `solc` npm
 * package directly (installed from the npm registry) instead of Hardhat's
 * built-in downloader, which tries to fetch the solc binary from
 * binaries.soliditylang.org -- a host this sandboxed dev environment
 * cannot reach.
 *
 * Produces Hardhat-compatible artifact JSON files so `npx hardhat test
 * --no-compile` and `npx hardhat run scripts/deploy.js --no-compile` work
 * exactly as if Hardhat had compiled it itself.
 *
 * On a normal machine with unrestricted internet access, this workaround
 * is unnecessary -- `npx hardhat compile` alone is sufficient.
 */

const fs = require("fs");
const path = require("path");
const solc = require("solc");

const CONTRACTS_DIR = path.join(__dirname, "..", "contracts");
const ARTIFACTS_DIR = path.join(__dirname, "..", "artifacts");
const NODE_MODULES = path.join(__dirname, "..", "node_modules");

function findImports(importPath) {
  // Resolve @openzeppelin/... imports (and any other node_modules import)
  // the same way Hardhat normally would.
  const candidates = [
    path.join(NODE_MODULES, importPath),
    path.join(CONTRACTS_DIR, importPath),
  ];
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      return { contents: fs.readFileSync(candidate, "utf8") };
    }
  }
  return { error: `File not found: ${importPath}` };
}

function compileContract(fileName, contractName) {
  const sourcePath = path.join(CONTRACTS_DIR, fileName);
  const source = fs.readFileSync(sourcePath, "utf8");

  const input = {
    language: "Solidity",
    sources: {
      [`contracts/${fileName}`]: { content: source },
    },
    settings: {
      optimizer: { enabled: true, runs: 200 },
      outputSelection: {
        "*": { "*": ["abi", "evm.bytecode", "evm.deployedBytecode"] },
      },
    },
  };

  const output = JSON.parse(solc.compile(JSON.stringify(input), { import: findImports }));

  if (output.errors) {
    const fatal = output.errors.filter((e) => e.severity === "error");
    output.errors.forEach((e) => console.log(e.formattedMessage));
    if (fatal.length > 0) {
      throw new Error(`Compilation failed with ${fatal.length} error(s).`);
    }
  }

  const compiled = output.contracts[`contracts/${fileName}`][contractName];

  const artifact = {
    _format: "hh-sol-artifact-1",
    contractName,
    sourceName: `contracts/${fileName}`,
    abi: compiled.abi,
    bytecode: "0x" + compiled.evm.bytecode.object,
    deployedBytecode: "0x" + compiled.evm.deployedBytecode.object,
    linkReferences: compiled.evm.bytecode.linkReferences || {},
    deployedLinkReferences: compiled.evm.deployedBytecode.linkReferences || {},
  };

  const outDir = path.join(ARTIFACTS_DIR, "contracts", fileName);
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(path.join(outDir, `${contractName}.json`), JSON.stringify(artifact, null, 2));

  console.log(`Compiled ${contractName} -> ${outDir}/${contractName}.json`);
  console.log(`  ABI entries: ${artifact.abi.length}, bytecode length: ${artifact.bytecode.length} chars`);

  return artifact;
}

compileContract("TrustGuardLedger.sol", "TrustGuardLedger");

compileContract("TrustGuardLedgerCompact.sol", "TrustGuardLedgerCompact");
console.log("\nManual compilation complete.");
