# arm-risc0

The RISC Zero implementation of the Anoma Resource Machine (ARM): its data types, its circuits, and the proving and verification of ARM transactions.

## Language

**Resource**:
A unit of state with a quantity, for example an amount of a token that a user owns. A transaction consumes and creates resources. A **persistent** resource stays until a later transaction consumes it. An **ephemeral** resource exists only in one transaction.

**Commitment / Nullifier / Tag**:
The commitment of a resource is a hash that shows that the resource exists. Its nullifier is a hash that shows that the resource is consumed. Only a holder of the **nullifier key** of the resource can calculate the nullifier, and the resource holds a commitment to this key. The tag of a resource in a transaction is its nullifier if the transaction consumes it, else its commitment.

**Commitment tree**:
A Merkle tree of all commitments. A transaction proves each resource that it consumes against a root of this tree. A **historical root** is a root of the commitment tree that the protocol adapter stores.

**Action / Transaction**:
An action is one ordered list of resources that it consumes and creates. A transaction is a list of actions.

**Action tree root**:
The root of a Merkle tree over the tags of an action, in the order of its list.

**Resource logic**:
The circuit that decides when a transaction can create or consume a resource. Its proof for a resource is the **logic proof** of that resource.

**Logic ref**:
The hash that identifies the code of a resource logic.

**Label ref**:
The hash of the data that separates the resources of one resource logic.

**Kind**:
The hash to curve of the logic ref and the label ref of a resource: a point on an elliptic curve.

**Kind base**:
The point that the compliance circuit multiplies by the quantity of a resource: its kind, or the point that a kind tree gives its kind.
_Avoid_: kind point

**Kind tree / Kind path / Alias**:
A kind tree is a Merkle tree of entries, each of which gives a kind a kind base. A kind path is the kind base of an entry and the Merkle path that proves that the entry is in the tree. Two kinds with the same kind base are aliases. A **conversion** consumes resources of one kind and creates resources of an alias.

**Kind tree root**:
The root of a kind tree. The root of the empty tree is `PADDING_LEAF`.

**In-circuit check**:
A check that a circuit makes: a proof of the circuit is valid only if the check holds. The **compliance checks** are the in-circuit checks of the compliance circuit.

**Out-of-circuit check**:
A check outside the circuits, for example in `transaction::verify` or in the protocol adapter.

**Compliance unit / Compliance proof**:
Each action has one compliance unit: a compliance witness, which is its private input, and a compliance instance, which is its public output. The compliance proof of the unit shows the compliance checks.

**Aggregation proof / Journal**:
One proof for all compliance proofs and resource logic proofs of a transaction. Its journal is its public output: the compliance verifying key, the kind tree root, and the resources, the delta point and the action tree root of each action.

**Delta proof**:
A signature over the action tree roots of a transaction. It shows that the transaction balances: for each kind base, the consumed and the created quantities are equal.

**Protocol adapter**:
The contract that verifies transactions on a chain and keeps the commitment tree and the set of all nullifiers. When it processes a resource, it makes the **external calls** of the resource to other contracts.

**Legacy protocol adapter**:
A protocol adapter that a chain used before the Galileo upgrade. It verifies proofs of the legacy version of arm-risc0.
