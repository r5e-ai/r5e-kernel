@id("kernel-node-authority")
permit (
  principal,
  action == R5e::Action::"admit",
  resource
)
when {
  context.node_authorized
};
