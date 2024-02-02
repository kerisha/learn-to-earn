debugger;

import { sizeInBits } from 'o1js/dist/node/provable/field-bigint';
import { EligibleAddressesWitness, Secrets } from './Secrets';
import { Field, Mina, PrivateKey, PublicKey, AccountUpdate, MerkleTree, Poseidon, Gadgets, Nullifier, MerkleMap, Signature } from 'o1js';

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

  it('should allow one address to submit only one message', async () => {
    // Use a nullifier
    await localDeploy();

    let nullifierData = senderAccount.toFields();
    let jsonNullifier = Nullifier.createTestNullifier(nullifierData, senderKey);
    console.log('nullifier root before', zkApp.nullifierRoot.get().toString());

    let txn = await Mina.transaction(senderAccount, () => {
      zkApp.executeNullifier(Nullifier.fromJSON(jsonNullifier));
    });
    await txn.prove();
    await txn.sign([senderKey]).send();
    console.log('nullifier root after', zkApp.nullifierRoot.get().toString());

    let verificationFailed = false;

    try {
      console.log('reusing nullifier');
      let message2 = senderAccount.toFields();
      let jsonNullifier2 = Nullifier.createTestNullifier(message2, senderKey);

      txn = await Mina.transaction(senderAccount, () => {
        zkApp.executeNullifier(Nullifier.fromJSON(jsonNullifier2));
      });
      console.log('reusing nullifier prove');
      await txn.prove();
      console.log('reusing nullifier sign and send');
      await txn.sign([senderKey]).send();
    } catch (e) {
      verificationFailed = true;
      console.log('error', e);
    }

    expect(verificationFailed).toEqual(true);
  });

  it('should not allow more than 100 eligible addresses to be stored', async () => {
    // Use a specific merkle tree that equates to 100 nodes/leaves...
    await localDeploy();

    let i = 0;
    let counter = 99;
    const addressesTree = new MerkleTree(8);
    for (; i < counter; i++) {
      addressesTree.setLeaf(BigInt(i), Poseidon.hash(senderAccount.toFields()));
    }

    let txn = await Mina.transaction(senderAccount, () => {
      zkApp.setAddressesCounter(Field(counter));
    });
    await txn.prove();
    await txn.sign([senderKey]).send();
    let addressesCount = zkApp.eligibleAddressesCount.get();
    console.log('addressesCount', addressesCount.toString());
    expect(addressesCount).toEqual(Field(counter));

    addressesTree.setLeaf(BigInt(counter), Poseidon.hash(senderAccount.toFields()));
    let witness = new EligibleAddressesWitness(addressesTree.getWitness(BigInt(counter)));

    // update transaction
    txn = await Mina.transaction(senderAccount, () => {
      zkApp.addEligibleAddress(senderAccount, witness);
    });
    await txn.prove();
    await txn.sign([senderKey]).send();

    let newCount = counter + 1;

    addressesCount = zkApp.eligibleAddressesCount.get();
    console.log('addressesCount', addressesCount.toString());
    console.log('new count ', newCount);
    expect(addressesCount).toEqual(Field(newCount));

    let failed = false;

    try {
      addressesTree.setLeaf(BigInt(newCount), Poseidon.hash(senderAccount.toFields()));
      witness = new EligibleAddressesWitness(addressesTree.getWitness(BigInt(newCount)));
      txn = await Mina.transaction(senderAccount, () => {
        zkApp.addEligibleAddress(senderAccount, witness);
      });
      await txn.prove();
      await txn.sign([senderKey]).send();
    } catch (e) {
      failed = true;
    }
    console.log(failed);
    expect(failed).toEqual(true);

  });

  it('should set all other flags in message to be false if flag 1 is true', async () => {
    // Bitwise operations
    const message = Field(0b100001);
    const expected = Field(0b000001);
    let actual = Field(0b0);

    actual = await zkApp.getValidMessage(message);
    expect(actual).toEqual(expected);

    const message2 = Field(0b100000);
    let actual2 = Field(0b0);

    actual2 = await zkApp.getValidMessage(message2);
    expect(actual2).toEqual(message2);
  });

  it('should set flag 3 to be true in message if flag 2 is true', async () => {
    // Bitwise operations
    const message = Field(0b010010);
    const expected = Field(0b010110);
    let actual = Field(0b0);

    actual = await zkApp.getValidMessage(message);
    console.log(actual);
    expect(actual).toEqual(expected);
  });

  it('should set flags 5 and 6 in message to be false if flag 4 is true', async () => {
    // Bitwise operations
    const message = Field(0b111000);
    const expected = Field(0b001000);
    let actual = Field(0b0);

    actual = await zkApp.getValidMessage(message);
    console.log(actual);
    expect(actual).toEqual(expected);
  });

  it('should follow all consecutive message rules', async () => {
    // Bitwise operations
    const message = Field(0b111011);
    const expected = Field(0b000101);
    let actual = Field(0b0);

    actual = await zkApp.getValidMessage(message);
    console.log(actual);
    expect(actual).toEqual(expected);
  });

  it('can save secret message', async () => {
    await localDeploy();

    let nullifierData = senderAccount.toFields();
    let jsonNullifier = Nullifier.createTestNullifier(nullifierData, senderKey);

    const addressesTree = new MerkleTree(8);
    addressesTree.setLeaf(0n, Poseidon.hash(senderAccount.toFields()));
    const addressWitness = new EligibleAddressesWitness(addressesTree.getWitness(0n));

    let txn = await Mina.transaction(senderAccount, () => {
      zkApp.addEligibleAddress(senderAccount, addressWitness);
    });
    await txn.prove();
    await txn.sign([senderKey]).send();

    let map = new MerkleMap();
    let secretMessage = Field(0b011101);
    let mapIndex = Field(1);
    map.set(mapIndex, Poseidon.hash(secretMessage.toFields()));
    let messageWitness = map.getWitness(mapIndex);

    let signature = Signature.create(senderKey, secretMessage.toFields());

    txn = await Mina.transaction(senderAccount, () => {
      zkApp.saveValidSecretMessages(Nullifier.fromJSON(jsonNullifier), secretMessage, messageWitness, signature, addressWitness);
    });
    await txn.prove();
    await txn.sign([senderKey]).send();

    let count = zkApp.messageCount.get();
    expect(count).toEqual(Field(1));
  });

  it('addresses that are NOT eligible can not deposit a message', async () => {
    await localDeploy();

    let nullifierData = senderAccount.toFields();
    let jsonNullifier = Nullifier.createTestNullifier(nullifierData, senderKey);

    const addressesTree = new MerkleTree(8);
    addressesTree.setLeaf(0n, Poseidon.hash(senderAccount.toFields()));
    const addressWitness = new EligibleAddressesWitness(addressesTree.getWitness(0n));

    // Eligible account with access to add message - sender account
    let txn = await Mina.transaction(senderAccount, () => {
      zkApp.addEligibleAddress(senderAccount, addressWitness);
    });
    await txn.prove();
    await txn.sign([senderKey]).send();

    let map = new MerkleMap();
    let secretMessage = Field(0b011101);
    let mapIndex = Field(1);
    map.set(mapIndex, Poseidon.hash(secretMessage.toFields()));
    let messageWitness = map.getWitness(mapIndex);

    // Account without access - deployer account... so therefore deployer key used
    let signature = Signature.create(deployerKey, secretMessage.toFields());

    let failed = false;
    try {
      txn = await Mina.transaction(deployerAccount, () => {
        zkApp.saveValidSecretMessages(Nullifier.fromJSON(jsonNullifier), secretMessage, messageWitness, signature, addressWitness);
      });
      await txn.prove();
      await txn.sign([senderKey]).send();
    } catch (error) {
      failed = true;
    }

    // Address for deployer account can not add a message
    expect(failed).toEqual(true);
  });

});