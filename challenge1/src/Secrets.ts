import { Field, SmartContract, state, State, method } from 'o1js';
export class Secrets extends SmartContract {
  @state(Field) num = State<Field>();
  @state(Field) counter = State<Field>();

  init() {
    super.init();
    this.num.set(Field(1));
    this.counter.set(Field(0));
  }

  @method update() {
    const currentState = this.num.getAndRequireEquals();
    const newState = currentState.add(2);
    this.num.set(newState);
  }

  @method addAddresses() {

  }

  @method addValidMessage() {
    const currentCounter = this.counter.getAndRequireEquals();
    const newCounter = currentCounter.add(1);
    this.counter.set(newCounter);
  }
}
