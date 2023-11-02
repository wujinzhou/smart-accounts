const { ethers, waffle } = require("hardhat");
const fs = require("fs");
const DeployInformation = JSON.parse(fs.readFileSync("depolyInfo.json"));

async function main() {
  const Handler = await ethers.getContractFactory("DefaultCallbackHandler");
  const handler = await Handler.deploy();
  console.log("handler deployed to:", handler.address);

  const SmartAccountFactory = await ethers.getContractFactory(
    "SmartAccountFactory",
  );
  const smartAccountFactory = await SmartAccountFactory.deploy(
    DeployInformation["EntryPoint"],
    handler.address,
  );
  console.log("smartAccountFactory deployed to:", smartAccountFactory.address);

  const Validator = await ethers.getContractFactory("ECDSAValidator");
  const validator = await Validator.deploy();
  console.log("validator deployed to:", validator.address);

  const DkimKeys = await ethers.getContractFactory("DkimKeys");
  const dkimKeys = await DkimKeys.deploy();

  const DkimVerifier = await ethers.getContractFactory("DkimVerifier");
  const dkimVerifier = await DkimVerifier.deploy(dkimKeys.address);

  const EmailValidator = await ethers.getContractFactory("EmailValidator");

  const emailValidator = await EmailValidator.deploy(dkimVerifier.address);
  console.log("emailValidator deployed to:", emailValidator.address);

  const SmartAccount = await ethers.getContractFactory("SmartAccount");
  const smartAccount = await SmartAccount.deploy(
    DeployInformation["EntryPoint"],
  );
  console.log("smartAccount deployed to:", smartAccount.address);

  const Secp256r1 = await ethers.getContractFactory(
    "contracts/validators/p256/Secp256r1.sol:Secp256r1",
  );
  const secp256r1 = await Secp256r1.deploy();
  console.log("secp256r1 deployed to:", secp256r1.address);

  const P256Validator = await ethers.getContractFactory(
    "contracts/validators/p256/P256Validator.sol:P256Validator",
  );
  const p256Validator = await P256Validator.deploy(secp256r1.address);
  console.log("p256Validator deployed to:", p256Validator.address);

  const WebauthnValidator =
    await ethers.getContractFactory("WebauthnValidator");
  const webauthnValidator = await WebauthnValidator.deploy(secp256r1);
  console.log("webauthnValidator deployed to:", webauthnValidator.address);

  const VerifyingPaymaster =
    await ethers.getContractFactory("VerifyingPaymaster");
  const verifyingPaymaster = await VerifyingPaymaster.deploy(
    ethers.utils.getAddress("0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789"),
    ethers.utils.getAddress("0xC9C44e626340032008b5414cB296619968115057"),
  );
  console.log("VerifyingPaymaster deployed to:", verifyingPaymaster.address);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
