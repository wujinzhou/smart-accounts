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
import {AbiCoder, ErrorFragment, hexlify, toUtf8Bytes} from 'ethers/lib/utils'
import { keccak256, toBuffer } from 'ethereumjs-util'

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

            const emailD = 'dennis.lee.okg@gmail.com'
            const accountOwner = "0x4E69Bc186B5161F2aBF85227b1Ec9CB004241eC4"
            const sig2 = "0x703477370324B521C0404458D7950F708D20268446BCCA5557E48D5421C4678DE05E5EAFADE9F81180300B6ABFCC7B2C7BABF81AC82487FCF4EFE91FCEEBAB1B947329BE2ED436C11E366C6B51A3B94F02BD5CE8FC2BCE01667C98F5BC6C408C90F863772656D6502ECB2C5515734FD080E268373E3474119808EC5912836706418A1F69F9248D01D21B1035ABE4C969488A19C8502FAB4E9BDF570930C1E5654A35EA2ED50AAEB40214FAC2733BD0D6E7A4854CB6307227D2451F95013EA3847C149F3AEFDCDF37777E7FD6CD1E8AC07ABCD7262C93BD5D598983D78B3389609F5FC05BB2EC9701587115A7D69FAD04CCD4ABC05F349F1EDC7DF8B22C2D8437"
            const data2 = "0x746F3A30787769746E65737340676D61696C2E636F6D0D0A7375626A6563743A3030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303061613336613730303030303030303030303030303030303030303030303030613335613330376639383663663831323630633735316464356232636135363266623263393637303030303030303030303030303030303030303030303030346536396263313836623531363166326162663835323237623165633963623030343234316563343030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030306330303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303132303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030343032643531386630366162643164316135383862613933646661333565623835643965323062336661313266306531633663616132336663323765383463316565316366383663356436373739313634383339636336346666396536636361386239333130373064376665313938393131336262356138396364313631613166393030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030343033323334333233373330333136353332333033343330333433393338363433303330363533383634333933303633363436333336333136353336363133373335333533383632363436363337333533353339363433303631363136323337333733393335363433363338333433343331363633363635333633313636333536310D0A6D6573736167652D69643A3C43414D6477674D765742654B6E766878726A6D5854332B732D427952486E476A7568755475574D505867427A64666536516841406D61696C2E676D61696C2E636F6D3E0D0A646174653A53756E2C2035204E6F7620323032332031313A31363A3432202B303830300D0A66726F6D3A44656E6E6973204C6565203C64656E6E69732E6C65652E6F6B6740676D61696C2E636F6D3E0D0A6D696D652D76657273696F6E3A312E300D0A646B696D2D7369676E61747572653A763D313B20613D7273612D7368613235363B20633D72656C617865642F72656C617865643B20643D676D61696C2E636F6D3B20733D32303233303630313B20743D313639393135343231333B20783D313639393735393031333B20646172613D676F6F676C652E636F6D3B20683D746F3A7375626A6563743A6D6573736167652D69643A646174653A66726F6D3A6D696D652D76657273696F6E3A66726F6D3A746F3A63633A7375626A656374203A646174653A6D6573736167652D69643A7265706C792D746F3B2062683D7261514636554546435431774F39366B4C7639746959596E65376B386755537353356A65305A53314B62773D3B20623D"
            
            const keyIdAdd = "242701e2040498d00e8d90cdc61e6a7558bdf7559d0aab7795d68441f6e61f5a"
            const keyBytesAdd = "0x2d518f06abd1d1a588ba93dfa35eb85d9e20b3fa12f0e1c6caa23fc27e84c1ee1cf86c5d6779164839cc64ff9e6cca8b931070d7fe1989113bb5a89cd161a1f9"
            await validator.createAccount(accountOwner, pubKeyBytes1, pubKeyId1, emailD)
            expect(await validator.emails(accountOwner)).to.equal(emailD)
            const initData = ethers.utils.defaultAbiCoder.encode(['bytes', 'bytes'], [sig2, data2])


            // email subject:
            /*
            0000000000000000000000000000000000000000000000000000000000aa36a70000000000000000000000000a35a307f986cf81260c751dd5b2ca562fb2c9670000000000000000000000004e69bc186b5161f2abf85227b1ec9cb004241ec4000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000012000000000000000000000000000000000000000000000000000000000000000402d518f06abd1d1a588ba93dfa35eb85d9e20b3fa12f0e1c6caa23fc27e84c1ee1cf86c5d6779164839cc64ff9e6cca8b931070d7fe1989113bb5a89cd161a1f9000000000000000000000000000000000000000000000000000000000000004032343237303165323034303439386430306538643930636463363165366137353538626466373535396430616162373739356436383434316636653631663561
            */
            //(uint chainId, address validator, address account, uint nonce, bytes memory keyBytes, string memory keyId)
            //const chainId = 0xaa36a7
            //const validatorAddr = "0x0a35a307F986cF81260c751dD5B2ca562fB2C967"  //not checked
            //const account = "0x4E69Bc186B5161F2aBF85227b1Ec9CB004241eC4"
            //const nonce = 0
            //const subject = ethers.utils.defaultAbiCoder.encode(
            //    ['uint256', 'address', 'address', 'uint256', 'bytes', 'string'], 
            //    [chainId, validatorAddr, account, nonce, pubKeyBytes2, pubKeyId2]
            //)
            //const s = ethers.utils.hexlify(subject)
            //console.log(s)

            // add the new passkey
            await validator.recover(initData)

            let key2 = await validator.publicKeys(accountOwner, keyIdAdd);
            expect(key2).to.equal(keyBytesAdd)
        })

        it('bind email with passkey', async () => {
            const emailDennis = 'dennis.lee@okg.com'
            const accountOwner = '0xc0A5E7202Cf0f8De928588c4F0db40571Ee19D7D'

            const pubKeyId3 = 'a2ef6294b5e3035ea09457130f8fe57377a8ec2fc2af89972410bbb4b3375115'
            const passkeyX3 = ethers.utils.hexZeroPad(ethers.utils.hexlify("0x68C246B13BB07C22220CBC4AA738F2A39FACAE1C64298523FD571EE6DA8C17EF"), 32)
            const passkeyY3 = ethers.utils.hexZeroPad(ethers.utils.hexlify("0x743FBCE7AC3C32AB5DBADC811E26D4C4626265B67F0CBA16BB216E63C23E47C7"), 32)
            const pubKeyBytes3 = ethers.utils.defaultAbiCoder.encode(['uint256', 'uint256'], [passkeyX3, passkeyY3])
            

            const clientDataJSONPre = '{"type":"webauthn.get","challenge":"'
            const clientDataJSONPost = '","origin":"http://localhost:3000","crossOrigin":false}'

            const realSig = ethers.utils.hexlify("0xd4fbc8b28d78f2a73a6e941c6f49493f24a8618461d2dc14d8122faccc2e306bf323c02f1d1f72ed09b42a94a0b181e1ce3b40bc3d16700bc0be4fea1dc604b9")
            
            const authenticatorData = ethers.utils.hexlify("0x49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000000")

            const singData = ethers.utils.defaultAbiCoder.encode(
                ['bytes', 'bytes', 'string', 'string', 'string'], 
                [realSig, authenticatorData, clientDataJSONPre, clientDataJSONPost, pubKeyId3]
            )
            //console.log(`singData:\n${singData}`)
            
            const callData = ethers.utils.defaultAbiCoder.encode(
                ['address', 'string', 'bytes'],
                [accountOwner, emailDennis, singData]
            )

            await validator.createAccount(accountOwner, pubKeyBytes3, pubKeyId3, '')
            expect(await validator.emails(accountOwner)).to.equal('')

            const challenge = '0x14dfd1567a908f17da103cb9872623e5d472f3cb3d181efd1455fba9afc86a41'
            const payload = ethers.utils.defaultAbiCoder.encode(['address', 'string'], [accountOwner, emailDennis])
            const dataToSign = hexlify(keccak256(toBuffer(payload)))
            expect(dataToSign).to.equal(challenge)

            //expect (await validator.callStatic.validateSignature(accountOwner, dataToSign, singData)).to.equal(0)

            await validator.bindEmail(callData)
            expect(await validator.emails(accountOwner)).to.equal(emailDennis)
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
