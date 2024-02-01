import { Secrets } from './Secrets';
import { Field, Mina, PrivateKey, PublicKey, AccountUpdate } from 'o1js';

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
      zkApp.addValidMessage();
    });
    await txn.prove();
    await txn.sign([senderKey]).send();

    const updatedNum = zkApp.counter.get();
    expect(updatedNum).toEqual(Field(1));
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
