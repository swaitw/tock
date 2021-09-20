pub trait OffsetBinaryWrite {
    fn write_buffer(&mut self, b: &[u8], offset: usize) -> Result<usize, ()>;
}
