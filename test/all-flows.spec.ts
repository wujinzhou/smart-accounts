import {expect} from 'chai'
import {ethers} from 'hardhat'
import {
    ECDSAValidator,
    EmailValidator,
    EntryPoint,
    Secp256r1,
    SmartAccount,
    SmartAccountFactory,
    WebauthnValidatorMock
} from '../src/types'
import {SignerWithAddress} from '@nomiclabs/hardhat-ethers/signers'
import {UserOperationBuilder, UserOperationMiddlewareCtx} from 'userop'
import {getGasPrice} from 'userop/dist/preset/middleware'
import {BytesLike} from 'ethers'
import {toUtf8Bytes} from 'ethers/lib/utils'

export async function deployEntryPoint(): Promise<EntryPoint> {
    const factory = await ethers.getContractFactory('EntryPoint')
    return (await factory.deploy()) as EntryPoint
}

describe('Smart Account tests', () => {
    let entryPoint: EntryPoint
    let accountFactory: SmartAccountFactory
    let accounts: SignerWithAddress[]
    let beneficiary: SignerWithAddress
    let sig = ethers.utils.hexlify('0x62AACA72155BB78B25306A1FC7E9FEB04112B2DAC5474E4F2404532238287AA5ED75C95EC37F4E06D6AF57889DCA777E21160CCF18D8C24492B1199E62F7DE23E015012D7C7EFC941FBF7EE45954054F4502D506816590E1F0BE01F25279B179BDF6796C26A171C4224710DEAC17FFC8B2806B4187A27B75A8E07CD5DB6C02730FE4E0D33A60D63D0A7B0AAC7C4B77088FDBEBD508F1779549BFF5984583E3DDF2D5BA1A06CCC12FDF1D14F3937046CAC79BC3D619BB5126A1EECE9AE9E96D18CFC58186D0B348EAD5C87AFB3EF43455EBC896BCBC5798BAF6E748E789549263B30411B5F5DBC74C5D970EE552E2A34651A6DA00C467CEF2D3B5F7F434CBDC22')
    let data = ethers.utils.hexlify('0x6D696D652D76657273696F6E3A312E300D0A66726F6D3A5461205461203C626174617473617240676D61696C2E636F6D3E0D0A646174653A4672692C2038204E6F7620323031392031313A34393A3236202B303730300D0A6D6573736167652D69643A3C43414B725F467361645476432B3333514F7143554252377357615A654758555876735F53457635414678444B516A68396B5A77406D61696C2E676D61696C2E636F6D3E0D0A7375626A6563743A5465737420676D61696C0D0A746F3A746174612074617461203C746174617474616940676D61696C2E636F6D3E0D0A646B696D2D7369676E61747572653A763D313B20613D7273612D7368613235363B20633D72656C617865642F72656C617865643B20643D676D61696C2E636F6D3B20733D32303136313032353B20683D6D696D652D76657273696F6E3A66726F6D3A646174653A6D6573736167652D69643A7375626A6563743A746F3B2062683D574F4B425275615A4B673965646F514C496C393573336B374534385553696C556C2F5A6C4C5430652F67303D3B20623D')

    let sig2 = ethers.utils.hexlify('0x')
    let data2 = ethers.utils.hexlify('0x')

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

            const {chainId} = await ethers.provider.getNetwork()
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
            await owner.sendTransaction({to: account, value: ethers.utils.parseEther('10')})

            await expect(entryPoint.handleOps([ctx.op], beneficiary.address)).to.be.revertedWith('AA24 signature error')

            signature = await owner.signMessage(ethers.utils.arrayify(ctx.getUserOpHash()))
            ctx.op.signature = ethers.utils.defaultAbiCoder.encode(['address', 'bytes'], [validator.address, signature])

            await entryPoint.handleOps([ctx.op], beneficiary.address)

            expect(ethers.provider.getCode(account)).not.to.equal('0x')
            expect(await validator.owner(account)).to.equal(owner.address)
        })
    })

    // describe('Webauthn validator account', () => {
    //     let owner: SignerWithAddress
    //     let validator: WebauthnValidator
    //     let secp256impl: Secp256r1
    //
    //     let pubKey: BytesLike
    //     let userOpHash: BytesLike
    //     let signature: BytesLike
    //
    //     before(async () => {
    //         owner = accounts[0]
    //         secp256impl = (await (await ethers.getContractFactory('Secp256r1')).deploy()) as Secp256r1
    //         const Webauthn = await ethers.getContractFactory('WebauthnValidator')
    //         validator = (await Webauthn.deploy(secp256impl.address)) as WebauthnValidator
    //
    //         expect(await validator.impl()).to.equal(secp256impl.address)
    //
    //         const passkeyX = ethers.utils.hexZeroPad(ethers.utils.hexlify("0xb131616540575881b59a5f1101f7cdd798efc127fd390d72bd52e6d15dcc713a"), 32)
    //         const passkeyY = ethers.utils.hexZeroPad(ethers.utils.hexlify("0xc41905b62b45ce1ff297c63e6651c0e6c4a1b4a22bc10411f25ddef6822079e6"), 32)
    //         pubKey = ethers.utils.defaultAbiCoder.encode(['uint256', 'uint256'], [passkeyX, passkeyY])
    //
    //         const realSig = ethers.utils.hexlify("0x25113a4a1f6c3256210f07ab54cbcfb40f0700f256656c60915aeaaefe965bc8344059d19f73a37fd562e259d67248ceb0c94aab10f2e405c3f70e03a190edc5")
    //         const authenticatorData = ethers.utils.hexlify("0x49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000000")
    //         const clientDataJSONPre = '{"type":"webauthn.get","challenge":"'
    //         const clientDataJSONPost = '","origin":"http://localhost:5000","crossOrigin":false}'
    //         userOpHash = ethers.utils.hexZeroPad(ethers.utils.hexlify("0x4eb0647e2b095293cde5ecb8779ad47e28ec09c115bc962430eb89404bb310e8"), 32)
    //
    //         signature = ethers.utils.defaultAbiCoder.encode(
    //             ['bytes', 'bytes', 'string', 'string'],
    //             [realSig, authenticatorData, clientDataJSONPre, clientDataJSONPost]
    //         )
    //     })
    //
    //     it('validate webauthn signature', async () => {
    //         const account = await accountFactory.getAddress([validator.address], [pubKey], 0)
    //         expect(await ethers.provider.getCode(account)).to.equal('0x')
    //
    //         await accountFactory.createAccount([validator.address], [pubKey], 0)
    //         expect(ethers.provider.getCode(account)).not.to.equal('0x')
    //
    //         let pk = await validator.pks(account)
    //         expect(pk).to.equal(pubKey)
    //
    //         let result = await validator.callStatic.validateSignature(account, userOpHash, signature)
    //         expect(result).to.equal(0)
    //
    //         /*
    //         const { chainId } = await ethers.provider.getNetwork()
    //         const builder = new UserOperationBuilder()
    //         builder.useMiddleware(getGasPrice(ethers.provider))
    //         builder.setSender(account)
    //         const op = await builder.buildOp(entryPoint.address, chainId)
    //         op.signature = ethers.utils.defaultAbiCoder.encode(['address', 'bytes'], [validator.address, signature])
    //
    //         const SmartAccount = await ethers.getContractFactory("SmartAccount")
    //         const smartAccount = SmartAccount.attach(account)
    //
    //         let result = await smartAccount.callStatic.<public_exposed>_validateSignature(op, userOpHash)
    //         expect(result).to.equal(0)
    //         */
    //
    //     })
    // })

    describe('Email recover webauthn account', () => {
        let owner: SignerWithAddress
        let validator: WebauthnValidatorMock
        let secp256impl: Secp256r1

        let pubKey: BytesLike
        let pubKey2: BytesLike

        before(async () => {
            owner = accounts[0]
            secp256impl = (await (await ethers.getContractFactory('Secp256r1')).deploy()) as Secp256r1
            const dkimKeysFactory = await ethers.getContractFactory("DkimKeys");
            const dkimKeys = await dkimKeysFactory.deploy();
            await dkimKeys.deployed();

            const dkimVerifierFactory = await ethers.getContractFactory('DkimVerifier');
            const dkimVerifier = await dkimVerifierFactory.deploy(dkimKeys.address);
            await dkimVerifier.deployed();

            const dkimDecoderFactory = await ethers.getContractFactory('DkimDecoder');
            const dkimDecoder = await dkimDecoderFactory.deploy();
            await dkimDecoder.deployed();

            const Webauthn = await ethers.getContractFactory('WebauthnValidatorMock', {
                libraries: {
                    DkimDecoder: dkimDecoder.address,
                },
            })

            validator = (await Webauthn.deploy(secp256impl.address, dkimVerifier.address)) as WebauthnValidatorMock

            expect(await validator.impl()).to.equal(secp256impl.address)

            const passkeyX = ethers.utils.hexZeroPad(ethers.utils.hexlify("0xb131616540575881b59a5f1101f7cdd798efc127fd390d72bd52e6d15dcc713a"), 32)
            const passkeyY = ethers.utils.hexZeroPad(ethers.utils.hexlify("0xc41905b62b45ce1ff297c63e6651c0e6c4a1b4a22bc10411f25ddef6822079e6"), 32)
            pubKey = ethers.utils.defaultAbiCoder.encode(['uint256', 'uint256'], [passkeyX, passkeyY])


            const passkeyX2 = ethers.utils.hexZeroPad(ethers.utils.hexlify(""), 32)
            const passkeyY2 = ethers.utils.hexZeroPad(ethers.utils.hexlify(""), 32)
            pubKey2 = ethers.utils.defaultAbiCoder.encode(['uint256', 'uint256'], [passkeyX2, passkeyY2])

        })

        it('create account use factory', async () => {
            const accountOwner = accounts[0].address
            await validator.createAccount(accountOwner, pubKey, "")
            expect(await validator.emails(accountOwner)).to.equal("")
            const initData = ethers.utils.defaultAbiCoder.encode(['bytes', 'bytes'], [sig2, data2])
            // (uint chainId, address validator, address account, uint nonce, bytes memory newPub)
            // const chainId = 1
            // const validatorAddr = validator.address
            // const account = accounts[0].address
            // const nonce = 0
            // const subject = ethers.utils.defaultAbiCoder.encode(['uint256', 'address', 'address', 'uint256', 'bytes'], [chainId, validatorAddr, account, nonce, pubKey2])
            // const res = ethers.utils.hexlify(subject)
            // console.log(res)

            await validator.recover(initData)
            expect(await validator.pks(accountOwner)).to.equal(pubKey2)
        })

    })


    describe('Email validator account', () => {
        let owner: SignerWithAddress
        let validator: EmailValidator

        before(async () => {
            owner = accounts[0]

            const dkimKeysFactory = await ethers.getContractFactory("DkimKeys");
            const dkimKeys = await dkimKeysFactory.deploy();
            await dkimKeys.deployed();

            const dkimVerifierFactory = await ethers.getContractFactory('DkimVerifier');
            const dkimVerifier = await dkimVerifierFactory.deploy(dkimKeys.address);
            await dkimVerifier.deployed();

            const dkimDecoderFactory = await ethers.getContractFactory('DkimDecoder');
            const dkimDecoder = await dkimDecoderFactory.deploy();
            await dkimDecoder.deployed();

            // const emailValidatorFactory = await ethers.getContractFactory('EmailValidator')
            // const validator = await emailValidatorFactory.deploy(dkim.address);
            // await validator.deployed();
            validator = (await (await ethers.getContractFactory('EmailValidator', {
                libraries: {
                    DkimDecoder: dkimDecoder.address,
                },
            })).deploy(dkimVerifier.address)) as EmailValidator
        })

        it('create account use factory', async () => {
            // TODO delete it
            const email = "batatsar@gmail.com"
            const emailBytes = toUtf8Bytes(email)
            const account = await accountFactory.getAddress([validator.address], [emailBytes], 0)
            expect(await ethers.provider.getCode(account)).to.equal('0x')
            await accountFactory.createAccount([validator.address], [emailBytes], 0)
            expect(ethers.provider.getCode(account)).not.to.equal('0x')
            expect(await validator.emails(account)).to.equal("batatsar@gmail.com")
        })

        it('create account use userop', async () => {
            const email = "batatsar@gmail.com"
            const emailBytes = toUtf8Bytes(email)
            const account = await accountFactory.getAddress([validator.address], [emailBytes], 1)
            expect(await ethers.provider.getCode(account)).to.equal('0x')

            const {chainId} = await ethers.provider.getNetwork()
            const builder = new UserOperationBuilder()
            builder.useMiddleware(getGasPrice(ethers.provider))
            builder.setSender(account)
            builder.setInitCode(
                ethers.utils.hexConcat([
                    accountFactory.address,
                    accountFactory.interface.encodeFunctionData('createAccount', [[validator.address], [emailBytes], 1]),
                ]),
            )
            builder.setVerificationGasLimit(8850000)
            builder.setCallGasLimit(10950000)
            builder.setPreVerificationGas(3000000)
            const op = await builder.buildOp(entryPoint.address, chainId)
            const ctx = new UserOperationMiddlewareCtx(op, entryPoint.address, chainId)

            const initData = ethers.utils.defaultAbiCoder.encode(['bytes', 'bytes'], [sig, data])
            ctx.op.signature = ethers.utils.defaultAbiCoder.encode(['address', 'bytes'], [validator.address, initData])
            await owner.sendTransaction({to: account, value: ethers.utils.parseEther('10')})

            await entryPoint.handleOps([ctx.op], beneficiary.address)

            expect(ethers.provider.getCode(account)).not.to.equal('0x')
            expect(await validator.emails(account)).to.equal(email)
        })
    })

    describe('Recovery ecdsa owner', () => {
        let owner: SignerWithAddress
        let validator: EmailValidator
        let ecdsaValidator: ECDSAValidator

        before(async () => {
            owner = accounts[0]

            const dkimKeysFactory = await ethers.getContractFactory("DkimKeys");
            const dkimKeys = await dkimKeysFactory.deploy();
            await dkimKeys.deployed();

            const dkimVerifierFactory = await ethers.getContractFactory('DkimVerifier');
            const dkimVerifier = await dkimVerifierFactory.deploy(dkimKeys.address);
            await dkimVerifier.deployed();

            const dkimDecoderFactory = await ethers.getContractFactory('DkimDecoder');
            const dkimDecoder = await dkimDecoderFactory.deploy();
            await dkimDecoder.deployed();

            validator = (await (await ethers.getContractFactory('EmailValidator', {
                libraries: {
                    DkimDecoder: dkimDecoder.address,
                },
            })).deploy(dkimVerifier.address)) as EmailValidator
            ecdsaValidator = (await (await ethers.getContractFactory('ECDSAValidator')).deploy()) as ECDSAValidator
        })

        it('recovery ecdsa owner', async () => {
            const email = "batatsar@gmail.com"
            const emailBytes = toUtf8Bytes(email)
            const account = await accountFactory.getAddress([validator.address, ecdsaValidator.address], [emailBytes, owner.address], 0)
            await owner.sendTransaction({to: account, value: ethers.utils.parseEther('10')})

            expect(await ethers.provider.getCode(account)).to.equal('0x')
            await accountFactory.createAccount([validator.address, ecdsaValidator.address], [emailBytes, owner.address], 0)
            expect(ethers.provider.getCode(account)).not.to.equal('0x')
            expect(await validator.emails(account)).to.equal("batatsar@gmail.com")
            expect(await ecdsaValidator.owner(account)).to.equal(owner.address)

            const SmartAccount = await ethers.getContractFactory("SmartAccount") as SmartAccount;
            const {chainId} = await ethers.provider.getNetwork()
            const builder = new UserOperationBuilder()
            builder.useMiddleware(getGasPrice(ethers.provider))
            builder.setSender(account)
            builder.setVerificationGasLimit(8850000)
            builder.setCallGasLimit(10950000)
            builder.setPreVerificationGas(3000000)
            builder.useMiddleware(getGasPrice(ethers.provider))

            ethers.utils.defaultAbiCoder.encode(['bytes', 'bytes'], [sig, data])

            const enableData = SmartAccount.interface.encodeFunctionData('enableValidator', [ecdsaValidator.address, beneficiary.address])
            builder.setCallData(SmartAccount.interface.encodeFunctionData('execute', [account, 0, enableData]))
            builder.setVerificationGasLimit(8850000)
            builder.setCallGasLimit(10950000)
            builder.setPreVerificationGas(3000000)
            const op = await builder.buildOp(entryPoint.address, chainId)
            const ctx = new UserOperationMiddlewareCtx(op, entryPoint.address, chainId)

            const initData = ethers.utils.defaultAbiCoder.encode(['bytes', 'bytes'], [sig, data])
            ctx.op.signature = ethers.utils.defaultAbiCoder.encode(['address', 'bytes'], [validator.address, initData])

            await entryPoint.handleOps([ctx.op], beneficiary.address)

            expect(ethers.provider.getCode(account)).not.to.equal('0x')
            expect(await validator.emails(account)).to.equal(email)
            expect(await ecdsaValidator.owner(account)).to.equal(beneficiary.address)
        })

    })

})
