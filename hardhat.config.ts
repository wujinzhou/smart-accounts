import * as dotenv from 'dotenv'
import '@nomiclabs/hardhat-etherscan'
import '@nomiclabs/hardhat-waffle'
import '@typechain/hardhat'
import 'hardhat-deploy'
import "hardhat-gas-reporter"
import "hardhat-tracer"


dotenv.config()

const PRIVATE_KEY = process.env.PRIVATE_KEY
const accounts = PRIVATE_KEY !== undefined ? [PRIVATE_KEY] : []

export default {
  networks: {
    hardhat: {
      allowUnlimitedContractSize: true,
    },
    dev: {
      url: "http://127.0.0.1:8545",
      accounts: accounts,
    },
    sepolia: {
      url: `https://eth-sepolia.public.blastapi.io`,
      accounts: accounts,
    },
  },
  solidity: {
    compilers: [{
      version: "0.8.19",
      settings: {
        viaIR: true,
        optimizer: {
          enabled: true,
          runs: 800,
        },
        metadata: {
          bytecodeHash: 'none',
        },
      }
    }, {
      version: "0.7.6",
      settings: {
        viaIR: true,
        optimizer: {
          enabled: true,
          runs: 800,
        },
        metadata: {
          bytecodeHash: 'none',
        },
      }
    }]
  },
  typechain: {
    outDir: "src/types"
  },
}
