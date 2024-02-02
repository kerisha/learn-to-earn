import { sizeInBits } from 'o1js/dist/node/provable/field-bigint';
import { EligibleAddressesWitness, Secrets } from './Secrets';
import { Field, Mina, PrivateKey, PublicKey, AccountUpdate, MerkleTree, Poseidon, Gadgets } from 'o1js';

/*
 * This file specifies how to test the `Add` example smart contract. It is safe to delete this file and replace
 * with your own tests.
 *
 * See https://docs.minaprotocol.com/zkapps for more info.
 */

let proofsEnabled = false;

describe('Secrets', () => {
  let deployerAccount: PublicKey,
    deployerKey: PrivateKey,
    senderAccount: PublicKey,
    senderKey: PrivateKey,
    zkAppAddress: PublicKey,
    zkAppPrivateKey: PrivateKey,
    zkApp: Secrets;

  beforeAll(async () => {
    if (proofsEnabled) await Secrets.compile();
  });

  beforeEach(() => {
    const Local = Mina.LocalBlockchain({ proofsEnabled });
    Mina.setActiveInstance(Local);
    ({ privateKey: deployerKey, publicKey: deployerAccount } =
      Local.testAccounts[0]);
    ({ privateKey: senderKey, publicKey: senderAccount } =
      Local.testAccounts[1]);
    zkAppPrivateKey = PrivateKey.random();
    zkAppAddress = zkAppPrivateKey.toPublicKey();
    zkApp = new Secrets(zkAppAddress);
  });

  async function localDeploy() {
    const txn = await Mina.transaction(deployerAccount, () => {
      AccountUpdate.fundNewAccount(deployerAccount);
      zkApp.deploy();
    });
    await txn.prove();
    // this tx needs .sign(), because `deploy()` adds an account update that requires signature authorization
    await txn.sign([deployerKey, zkAppPrivateKey]).send();
  }

  it('generates and deploys the `Secrets` smart contract', async () => {
    await localDeploy();
    const num = zkApp.counter.get();
    expect(num).toEqual(Field(0));
  });

  it('correctly updates the counter state on the `Secrets` smart contract', async () => {
    await localDeploy();

    // update transaction
    const txn = await Mina.transaction(senderAccount, () => {
      zkApp.incrementTestCounter();
    });
    await txn.prove();
    await txn.sign([senderKey]).send();

    const updatedNum = zkApp.counter.get();
    expect(updatedNum).toEqual(Field(1));
  });

  it('can add an eligible address', async () => {
    await localDeploy();

    const addressesTree = new MerkleTree(8);
    addressesTree.setLeaf(0n, Poseidon.hash(senderAccount.toFields()));
    const witness = new EligibleAddressesWitness(addressesTree.getWitness(0n));

    // update transaction
    let txn = await Mina.transaction(senderAccount, () => {
      zkApp.addEligibleAddress(senderAccount, witness);
    });
    await txn.prove();
    await txn.sign([senderKey]).send();

    let treeRoot = zkApp.eligibleAddressesRoot.get();
    console.log('first root', treeRoot.toString());
    expect(treeRoot).toEqual(addressesTree.getRoot());

    addressesTree.setLeaf(1n, Poseidon.hash(deployerAccount.toFields()));
    const witness2 = new EligibleAddressesWitness(addressesTree.getWitness(1n));

    // update transaction
    txn = await Mina.transaction(deployerAccount, () => {
      zkApp.addEligibleAddress(deployerAccount, witness2);
    });
    await txn.prove();
    await txn.sign([deployerKey]).send();

    treeRoot = zkApp.eligibleAddressesRoot.get();
    console.log('second root', treeRoot.toString());
    expect(treeRoot).toEqual(addressesTree.getRoot());
  });

  it('can get length of bits', async () => {
    let a = Field(0b0101);
    let b = Field(0b0011);

    let c = Gadgets.xor(a, b, 9); // xor-ing 4 bits
    console.log(c);
    c.assertEquals(0b0110);
    //c.assertEquals(0b10);
  });

  it('should only allow one address to submit one test message', async () => {
    // Use a nullifier
  });

  it('should only store eligible administrator addresses', async () => {
    // Use a merkle tree / merkle map for storage
  });

  it('should not allow more than 100 eligible addresses to be stored', async () => {
    // Use a specific merkle tree that equates to 100 nodes/leaves...
  });

  it('should set all other flags in message to be false if flag 1 is false', async () => {
    // Bitwise operations
  });

  it('should set flag 3 to be true in message if flag 2 is true', async () => {
    // Bitwise operations

  });

  it('should set flags 5 and 6 in message to be true if flag 4 is true', async () => {
    // Bitwise operations

  });

  it('', async () => {

  });
});
