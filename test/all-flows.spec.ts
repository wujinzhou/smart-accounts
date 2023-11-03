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
import {ErrorFragment, toUtf8Bytes} from 'ethers/lib/utils'

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

    let emailJZ = 'j1nzh0u@yahoo.com'
    let sig2 = ethers.utils.hexlify('0x15BFA39D212CA50773834DED02552EF46A5D2AEA815BE73FBD0486EB22A90905DAF6732FC8E48F7C40F237BAB71543014D90712A3BBDB99A92289936E906405A1EF11BC8E3F2AE523F36DE38604C0CCEFB2E143F7DBC58045CE2ECA5A1A75A3810DBEAE709EBA27726B397608787D1C8CD46928BF1E55BAADAC9F4E67BF2ACE9A319CC5E98E1F5C3CE9532915882F6C90678243C17B463090962CE7B8005B15660260566124029868DEE6C33E0AE6D85295B7E24D1580E76DC5FD5C13B05577DB8168EE13194758916800ADAD16DE85A6D4C42240731D1F61ECFC2DDA0BE4E0F0E9987CDED5F1D3EEE0B2C3F7E40C02CCE6D4713332392CEE6636A6649E180DF')
    let data2 = ethers.utils.hexlify('0x646174653A5468752C2032204E6F7620323032332031383A32393A3430202B303030302028555443290D0A66726F6D3A226A316E7A683075407961686F6F2E636F6D22203C6A316E7A683075407961686F6F2E636F6D3E0D0A7265706C792D746F3A226A316E7A683075407961686F6F2E636F6D22203C6A316E7A683075407961686F6F2E636F6D3E0D0A746F3A4A696E7A686F75205775203C77756A696E7A686F75406C6976652E636F6D3E0D0A7375626A6563743A3030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303130303030303030303030303030303030303030303030303061353163316663326630643161316238343934656431666533313264376333613738656439316330303030303030303030303030303030303030303030303030663339666436653531616164383866366634636536616238383237323739636666666239323236363030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030306330303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303132303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030343061623030313530363565666663303138363131653139363039633966386335633266303036333535656461373237306165363639373637323964656562633832336563643433323032306666333535643365363763343366346266656630386666326530366230613134623433643735323766323964613461353063383435373030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030326234643661366435323337333936333437356634333338363936383463343333313330373436633665356134613733363435313533333435393332363937353336343636643339353736363433353134323333343337373030303030303030303030303030303030303030303030303030303030303030303030303030303030300D0A7265666572656E6365733A3C3738303738363430392E3330343730352E313639383934393738303937342E726566406D61696C2E7961686F6F2E636F6D3E0D0A646B696D2D7369676E61747572653A763D313B20613D7273612D7368613235363B20633D72656C617865642F72656C617865643B20643D7961686F6F2E636F6D3B20733D73323034383B20743D313639383934393738323B2062683D307A2F6F6671627A5457727A6E6431672F656A504A382F4E68363634306C4478626F325864635A316A44493D3B20683D446174653A46726F6D3A5265706C792D546F3A546F3A5375626A6563743A5265666572656E6365733A46726F6D3A5375626A6563743A5265706C792D546F3B20623D')

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

        let pubKeyBytes1: BytesLike
        let pubKeyId1: string

        let pubKeyBytes2: BytesLike
        let pubKeyId2: string

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
            pubKeyBytes1 = ethers.utils.defaultAbiCoder.encode(['uint256', 'uint256'], [passkeyX, passkeyY])
            pubKeyId1 = "YASW8qKx4iID-zg9Y6lQbEjJNAZuppzryrNT7-9r3kA"

            const passkeyX2 = ethers.utils.hexZeroPad(ethers.utils.hexlify("0xab0015065effc018611e19609c9f8c5c2f006355eda7270ae66976729deebc82"), 32)
            const passkeyY2 = ethers.utils.hexZeroPad(ethers.utils.hexlify("0x3ecd432020ff355d3e67c43f4bfef08ff2e06b0a14b43d7527f29da4a50c8457"), 32)
            pubKeyBytes2 = ethers.utils.defaultAbiCoder.encode(['uint256', 'uint256'], [passkeyX2, passkeyY2])
            pubKeyId2 = 'MjmR79cG_C8ihLC10tlnZJsdQS4Y2iu6Fm9WfCQB3Cw'

        })

        it('add passkey with email', async () => {
            const accountOwner = accounts[0].address
            await validator.createAccount(accountOwner, pubKeyBytes1, pubKeyId1, emailJZ)
            expect(await validator.emails(accountOwner)).to.equal(emailJZ)
            const initData = ethers.utils.defaultAbiCoder.encode(['bytes', 'bytes'], [sig2, data2])

            //(uint chainId, address validator, address account, uint nonce, bytes memory keyBytes, string memory keyId)
            const chainId = 1
            const validatorAddr = validator.address
            const account = accounts[0].address
            const nonce = 0
            const subject = ethers.utils.defaultAbiCoder.encode(
                ['uint256', 'address', 'address', 'uint256', 'bytes', 'string'], 
                [chainId, validatorAddr, account, nonce, pubKeyBytes2, pubKeyId2]
            )
            const res = ethers.utils.hexlify(subject)
            //console.log(res)

            // add the new passkey
            await validator.recover(initData)

            let key2 = await validator.publicKeys(account, pubKeyId2);
            expect(key2).to.equal(pubKeyBytes2)
        })

        it('add email with passkey', async () => {
            const accountOwner = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266'

            const pubKeyId3 = 'FI9HYGq3Ph_MjaKF4_gY0kqS2Zg'
            const passkeyX3 = ethers.utils.hexZeroPad(ethers.utils.hexlify("0xab0015065effc018611e19609c9f8c5c2f006355eda7270ae66976729deebc82"), 32)
            const passkeyY3 = ethers.utils.hexZeroPad(ethers.utils.hexlify("0x3ecd432020ff355d3e67c43f4bfef08ff2e06b0a14b43d7527f29da4a50c8457"), 32)
            const pubKeyBytes3 = ethers.utils.defaultAbiCoder.encode(['uint256', 'uint256'], [passkeyX3, passkeyY3])
            

            const clientDataJSONPre = '{"type":"webauthn.get","challenge":"'
            const clientDataJSONPost = '","origin":"https://localhost:5000"}'

            const realSig = ethers.utils.hexlify("0xc0631f735112c2ed2576b0ea0d0633c22190445a5bd9efcf046fbf5819f2d7e72bf522fbedb55c77ec26ffca77decca05a10a0f15c65eab7aa891badda8438bd")
            
            const authenticatorData = ethers.utils.hexlify("0x49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97631d00000000")

            const singData = ethers.utils.defaultAbiCoder.encode(
                ['bytes', 'bytes', 'string', 'string', 'string'], 
                [realSig, authenticatorData, clientDataJSONPre, clientDataJSONPost, pubKeyId3]
            )

            const callData = ethers.utils.defaultAbiCoder.encode(
                ['address', 'string', 'bytes'],
                [accountOwner, emailJZ, singData]
            )

            await validator.createAccount(accountOwner, pubKeyBytes3, pubKeyId3, '')
            expect(await validator.emails(accountOwner)).to.equal('')

            //challenge = '0x13bd0b287cb48a07fc91b20f924ef697b0c82a6658c8c124e6207a1aeb864b67'
            await validator.bindEmail(callData)
            expect(await validator.emails(accountOwner)).to.equal(emailJZ)
        
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
