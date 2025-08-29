# Binary tree aggregation circuit
The [circuit for a single step in a binary tree aggregation](methods/guest/src/main.rs) does the following:
* verify the step output for the step program,
* if not the base case, verify the two input aggregations,
* hash the step output and step program with the input running hashes.