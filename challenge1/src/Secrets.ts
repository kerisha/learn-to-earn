import { Field, SmartContract, state, State, method, PublicKey, MerkleWitness, Poseidon } from 'o1js';

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

  @method addValidMessage(message: Field) {

  }
}
