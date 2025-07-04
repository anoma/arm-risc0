# Sequential aggregation circuit
The [circuit of a single step in a sequential aggregation](methods/guest/src/main.rs) does the following:
 * verify the step output for the step program,
 * if not the base case, verify the input aggregation,
 * hash the step output and step program with the input running hash.