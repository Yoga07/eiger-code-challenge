/// A Node wrapper that works as a generic interface for a node implementation
pub trait NodeWrapper {

    fn init_node();

    fn handshake();

    fn close_conns();
}