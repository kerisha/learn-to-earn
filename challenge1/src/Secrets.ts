import { Field, SmartContract, state, State, method, PublicKey, MerkleWitness, Poseidon, Circuit, Provable, Gadgets } from 'o1js';

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

  init() {
    super.init();
    this.num.set(Field(1));
    this.counter.set(Field(0));
    this.messageCount.set(Field(0));
    this.eligibleAddressesCount.set(Field(0));
    this.eligibleAddressesRoot.set(Field(0));
    this.messagesRoot.set(Field(0));
    this.nullifierRoot.set(Field(0));
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
    this.eligibleAddressesRoot.getAndRequireEquals();
    const addressCount = this.eligibleAddressesCount.getAndRequireEquals();

    addressCount.assertLessThanOrEqual(100);
    const hash = Poseidon.hash(address.toFields());
    const newRoot = witness.calculateRoot(hash);
    this.eligibleAddressesRoot.set(newRoot);
    this.eligibleAddressesCount.set(addressCount.add(1));
  }

  @method getValidMessage(message: Field) {
    let mask = Field(0b00111111);
    let sixBitsMessage = Gadgets.and(message, mask, 6);

    let flag1Mask = Field(0b000001);
    let flag2Mask = Field(0b000010);
    let flag3Mask = Field(0b000100);
    let flag4Mask = Field(0b001000);
    let flag5Mask = Field(0b010000);
    let flag6Mask = Field(0b100000);

    let flag1 = Gadgets.and(sixBitsMessage, flag1Mask, 6);
    let flag2 = Gadgets.and(sixBitsMessage, flag2Mask, 6);
    let flag3 = Gadgets.and(sixBitsMessage, flag3Mask, 6);
    let flag4 = Gadgets.and(sixBitsMessage, flag4Mask, 6);

    let flag1Set = flag1.equals(1); // 0b00000000
    let flag2Set = flag2.equals(2); // 0b00000010
    let flag4Set = flag4.equals(8); //0b00001000

    // If flag 1 is true, all other flags must be false 
    sixBitsMessage = Provable.if(flag1Set, Field(1), sixBitsMessage);

    // If flag 2 is true, flag 3 must also be true
    const notThirdMask = Gadgets.not(flag3Mask, 6);
    let flag2res1 = Gadgets.and(notThirdMask, sixBitsMessage, 6);
    let flag2res2 = Gadgets.xor(flag2res1, flag3Mask, 6);
    sixBitsMessage = Provable.if(flag2Set, flag2res2, sixBitsMessage);

    let not5Mask = Gadgets.not(flag5Mask, 6);
    let not6Mask = Gadgets.not(flag6Mask, 6);
    let part1 = Gadgets.and(sixBitsMessage, not5Mask, 6);
    // If flag 4 is true, flag 5 and 6 must be false
    sixBitsMessage = Provable.if(flag4Set, Gadgets.and(part1, not6Mask, 6), sixBitsMessage);

    return sixBitsMessage;
  }
}
