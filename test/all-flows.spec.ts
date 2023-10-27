import { expect } from 'chai'
import { ethers } from 'hardhat'
import { ECDSAValidator, WebauthnValidator, P256Validator, Secp256r1, EntryPoint, SmartAccountFactory } from '../src/types'
import { SignerWithAddress } from '@nomiclabs/hardhat-ethers/signers'
import { UserOperationBuilder, UserOperationMiddlewareCtx } from 'userop'
import { getGasPrice } from 'userop/dist/preset/middleware'
import { BytesLike, utils } from 'ethers'
import { AbiCoder, Hexable } from 'ethers/lib/utils'

export async function deployEntryPoint(): Promise<EntryPoint> {
  const factory = await ethers.getContractFactory('EntryPoint')
  return (await factory.deploy()) as EntryPoint
}

describe('Smart Account tests', () => {
  let entryPoint: EntryPoint
  let accountFactory: SmartAccountFactory
  let accounts: SignerWithAddress[]
  let beneficiary: SignerWithAddress

  before(async () => {
    accounts = await ethers.getSigners()
    beneficiary = accounts[1]
    entryPoint = await deployEntryPoint()

    const handler = await (await ethers.getContractFactory('DefaultCallbackHandler')).deploy()
    accountFactory = (await (
      await ethers.getContractFactory('SmartAccountFactory')
    ).deploy(entryPoint.address, handler.address)) as SmartAccountFactory
  })

  describe('ECDSA validator account', () => {
    let owner: SignerWithAddress
    let validator: ECDSAValidator

    before(async () => {
      owner = accounts[0]
      validator = (await (await ethers.getContractFactory('ECDSAValidator')).deploy()) as ECDSAValidator
    })

    it('create account use factory', async () => {
      const account = await accountFactory.getAddress([validator.address], [owner.address], 0)
      expect(await ethers.provider.getCode(account)).to.equal('0x')

      await accountFactory.createAccount([validator.address], [owner.address], 0)
      expect(ethers.provider.getCode(account)).not.to.equal('0x')
      expect(await validator.owner(account)).to.equal(owner.address)
    })

    it('create account use userop', async () => {
      const account = await accountFactory.getAddress([validator.address], [owner.address], 1)
      expect(await ethers.provider.getCode(account)).to.equal('0x')

      const { chainId } = await ethers.provider.getNetwork()
      const builder = new UserOperationBuilder()
      builder.useMiddleware(getGasPrice(ethers.provider))
      builder.setSender(account)
      builder.setInitCode(
        ethers.utils.hexConcat([
          accountFactory.address,
          accountFactory.interface.encodeFunctionData('createAccount', [[validator.address], [owner.address], 1]),
        ]),
      )
      builder.setVerificationGasLimit(350000)
      const op = await builder.buildOp(entryPoint.address, chainId)
      const ctx = new UserOperationMiddlewareCtx(op, entryPoint.address, chainId)
      let signature = await beneficiary.signMessage(ethers.utils.arrayify(ctx.getUserOpHash()))
      ctx.op.signature = ethers.utils.defaultAbiCoder.encode(['address', 'bytes'], [validator.address, signature])

      // deposit gas
      await owner.sendTransaction({ to: account, value: ethers.utils.parseEther('10') })

      await expect(entryPoint.handleOps([ctx.op], beneficiary.address)).to.be.revertedWith('AA24 signature error')

      signature = await owner.signMessage(ethers.utils.arrayify(ctx.getUserOpHash()))
      ctx.op.signature = ethers.utils.defaultAbiCoder.encode(['address', 'bytes'], [validator.address, signature])

      await entryPoint.handleOps([ctx.op], beneficiary.address)

      expect(ethers.provider.getCode(account)).not.to.equal('0x')
      expect(await validator.owner(account)).to.equal(owner.address)
    })
  })

  describe('Webauthn validator account', () => {
    let owner: SignerWithAddress
    let validator: WebauthnValidator
    let secp256impl: Secp256r1

    let pubKey: BytesLike
    let userOpHash: BytesLike
    let signature: BytesLike

    before(async () => {
      owner = accounts[0]
      secp256impl = (await (await ethers.getContractFactory('Secp256r1')).deploy()) as Secp256r1
      const Webauthn = await ethers.getContractFactory('WebauthnValidator')
      validator = (await Webauthn.deploy(secp256impl.address)) as WebauthnValidator

      expect(await validator.impl()).to.equal(secp256impl.address)

      const passkeyX = ethers.utils.hexZeroPad(ethers.utils.hexlify("0xb131616540575881b59a5f1101f7cdd798efc127fd390d72bd52e6d15dcc713a"), 32)
      const passkeyY = ethers.utils.hexZeroPad(ethers.utils.hexlify("0xc41905b62b45ce1ff297c63e6651c0e6c4a1b4a22bc10411f25ddef6822079e6"), 32)
      pubKey = ethers.utils.defaultAbiCoder.encode(['uint256', 'uint256'], [passkeyX, passkeyY])

      const realSig = ethers.utils.hexlify("0x25113a4a1f6c3256210f07ab54cbcfb40f0700f256656c60915aeaaefe965bc8344059d19f73a37fd562e259d67248ceb0c94aab10f2e405c3f70e03a190edc5")
      const authenticatorData = ethers.utils.hexlify("0x49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000000")
      const clientDataJSONPre = '{"type":"webauthn.get","challenge":"'
      const clientDataJSONPost = '","origin":"http://localhost:5000","crossOrigin":false}'
      userOpHash = ethers.utils.hexZeroPad(ethers.utils.hexlify("0x4eb0647e2b095293cde5ecb8779ad47e28ec09c115bc962430eb89404bb310e8"), 32)

      signature = ethers.utils.defaultAbiCoder.encode(
        ['bytes', 'bytes', 'string', 'string'], 
        [realSig, authenticatorData, clientDataJSONPre, clientDataJSONPost]
      )
    })

    it('validate webauthn signature', async () => {
      const account = await accountFactory.getAddress([validator.address], [pubKey], 0)
      expect(await ethers.provider.getCode(account)).to.equal('0x')

      await accountFactory.createAccount([validator.address], [pubKey], 0)
      expect(ethers.provider.getCode(account)).not.to.equal('0x')

      let pk = await validator.pks(account)
      expect(pk).to.equal(pubKey)
      
      let result = await validator.callStatic.validateSignature(account, userOpHash, signature)
      expect(result).to.equal(0)

      /*
      const { chainId } = await ethers.provider.getNetwork()
      const builder = new UserOperationBuilder()
      builder.useMiddleware(getGasPrice(ethers.provider))
      builder.setSender(account)
      const op = await builder.buildOp(entryPoint.address, chainId)
      op.signature = ethers.utils.defaultAbiCoder.encode(['address', 'bytes'], [validator.address, signature])
      
      const SmartAccount = await ethers.getContractFactory("SmartAccount")
      const smartAccount = SmartAccount.attach(account)

      let result = await smartAccount.callStatic.<public_exposed>_validateSignature(op, userOpHash)
      expect(result).to.equal(0)
      */

    })
  })
  
})
