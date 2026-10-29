require("@nomicfoundation/hardhat-toolbox");

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    version: "0.8.24",
    settings: {
      optimizer: { enabled: true, runs: 200 },
    },
  },
  networks: {
    // Local Hardhat network -- used for this submission's development,
    // testing, and demo. To move to a public testnet (e.g. Polygon Amoy,
    // Ethereum Sepolia) for later phases, add a network block here with an
    // RPC URL (Alchemy/Infura) and a funded wallet private key, e.g.:
    //
    // sepolia: {
    //   url: process.env.SEPOLIA_RPC_URL,
    //   accounts: [process.env.PRIVATE_KEY],
    // },
    hardhat: {},
    localhost: {
      url: "http://127.0.0.1:8545",
    },
  },
};
