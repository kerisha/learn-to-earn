import { Field, SmartContract, state, State, method, PublicKey, MerkleWitness, Poseidon, Circuit, Provable, Gadgets, Nullifier, MerkleMapWitness, Signature, MerkleMap } from 'o1js';

export class SecretMessageWitness extends MerkleWitness(256) { }
export class EligibleAddressesWitness extends MerkleWitness(8) { }

export class Secrets extends SmartContract {
  @state(Field) num = State<Field>();
  @state(Field) counter = State<Field>();

  @state(Field) messageCount = State<Field>();
  @state(Field) eligibleAddressesCount = State<Field>();
  @state(Field) eligibleAddressesRoot = State<Field>();
  @state(Field) messagesRoot = State<Field>();
  @state(Field) nullifierRoot = State<Field>();

  NullifierTree = new MerkleMap();

  init() {
    super.init();
    this.num.set(Field(1));
    this.counter.set(Field(0));
    this.messageCount.set(Field(0));
    this.eligibleAddressesCount.set(Field(0));
    this.eligibleAddressesRoot.set(Field(0));
    this.messagesRoot.set(Field(0));
    this.nullifierRoot.set(this.NullifierTree.getRoot());
  }

  @method setEligibleAddressesRoot(newRoot: Field) {
    this.eligibleAddressesRoot.getAndRequireEquals();
    this.eligibleAddressesRoot.set(newRoot);
  }

  @method setAddressesCounter(count: Field) {
    this.eligibleAddressesCount.getAndRequireEquals();
    this.eligibleAddressesCount.set(count);
  }

  @method update() {
    const currentState = this.num.getAndRequireEquals();
    const newState = currentState.add(2);
    this.num.set(newState);
  }

  @method incrementTestCounter() {
    const currentCounter = this.counter.getAndRequireEquals();
    const newCounter = currentCounter.add(1);
    this.counter.set(newCounter);
  }

  @method addEligibleAddress(address: PublicKey, witness: EligibleAddressesWitness) {
    // validate max number of addresses can not go over 100
    const addressCount = this.eligibleAddressesCount.getAndRequireEquals();
    const newAddressCount = addressCount.add(1);
    newAddressCount.assertLessThanOrEqual(100);

    // update the eligible addresses root
    this.eligibleAddressesRoot.getAndRequireEquals();
    const hash = Poseidon.hash(address.toFields());
    const newRoot = witness.calculateRoot(hash);
    this.eligibleAddressesRoot.set(newRoot);
    this.eligibleAddressesCount.set(newAddressCount);
  }

  @method getValidMessage(message: Field): Field {
    let mask: Field = Field(0b00111111);
    // Take last 6 bits
    let sixBitsMessage: Field = Gadgets.and(message, mask, 6);

    let flag1Mask: Field = Field(0b000001);
    let flag2Mask: Field = Field(0b000010);
    let flag3Mask: Field = Field(0b000100);
    let flag4Mask: Field = Field(0b001000);

    let flag1: Field = Gadgets.and(sixBitsMessage, flag1Mask, 6);
    let flag2: Field = Gadgets.and(sixBitsMessage, flag2Mask, 6);
    let flag4: Field = Gadgets.and(sixBitsMessage, flag4Mask, 6);

    let flag1Set = flag1.equals(1); // 0b00000000
    let flag2Set = flag2.equals(2); // 0b00000010
    let flag4Set = flag4.equals(8); // 0b00001000

    // If flag 1 is true, all other flags must be false 
    sixBitsMessage = Provable.if(flag1Set, Field(1), sixBitsMessage);

    // If flag 2 is true, flag 3 must also be true
    const notThirdMask: Field = Gadgets.not(flag3Mask, 6);
    let flag2res1: Field = Gadgets.and(notThirdMask, sixBitsMessage, 6);
    let flag2res2: Field = Gadgets.xor(flag2res1, flag3Mask, 6);
    sixBitsMessage = Provable.if(flag2Set, flag2res2, sixBitsMessage);

    // If flag 4 is true, flag 5 and 6 must be false
    let flag4SetMask: Field = Field(0b001111);
    sixBitsMessage = Provable.if(flag4Set, Gadgets.and(sixBitsMessage, flag4SetMask, 6), sixBitsMessage);

    return sixBitsMessage;
  }

  @method executeNullifier(nullifier: Nullifier) {

    let nullifierRoot = this.nullifierRoot.getAndRequireEquals();

    nullifier.verify(this.sender.toFields());
    let nullfierWitness = Provable.witness(MerkleMapWitness, () =>
      this.NullifierTree.getWitness(nullifier.key())
    );
    // Prevent a user/address from adding multiple addresses
    nullifier.assertUnused(nullfierWitness, nullifierRoot);
    let newRoot = nullifier.setUsed(nullfierWitness);
    this.nullifierRoot.set(newRoot);
  }

  @method saveValidSecretMessages(nullifier: Nullifier, secretMessage: Field, messageWitness: MerkleMapWitness, signature: Signature, addressWitness: EligibleAddressesWitness) {

    // Prevent a user/address from adding multiple addresses
    this.executeNullifier(nullifier);

    // Current user check if they are eligible
    const userAddressRoot = this.eligibleAddressesRoot.getAndRequireEquals();
    signature.verify(this.sender, secretMessage.toFields()).assertTrue();
    const witnessRoot = addressWitness.calculateRoot(Poseidon.hash(this.sender.toFields()));
    witnessRoot.assertEquals(userAddressRoot);

    // Convert secret message into a valid message
    let convertedMessage: Field = this.getValidMessage(secretMessage);

    // Update messages root
    this.messagesRoot.getAndRequireEquals();
    const [messageRoot, _] = messageWitness.computeRootAndKey(Poseidon.hash(convertedMessage.toFields()));
    this.messagesRoot.set(messageRoot);

    // Update state counter
    const currentState = this.messageCount.getAndRequireEquals();
    const newState = currentState.add(1);
    this.messageCount.set(newState);
  }
}
