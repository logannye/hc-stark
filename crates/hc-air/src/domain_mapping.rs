pub fn domain_size(trace_len: usize) -> usize {
    trace_len.next_power_of_two()
}
