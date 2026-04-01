//! Fixed-size ring buffer for failure timestamps.
//!
//! Capacity equals `max_retry`. When the buffer is full and the span from
//! oldest to newest is within `find_time`, a ban threshold is reached.
//! Threshold check is O(1).

/// A fixed-capacity ring buffer of `i64` unix timestamps.
#[derive(Debug, Clone)]
pub struct CircularTimestamps {
    buf: Vec<i64>,
    /// Points to the next write position (also the oldest entry when full).
    head: usize,
    len: usize,
}

impl CircularTimestamps {
    /// Create a new buffer with the given capacity (typically `max_retry`).
    pub fn new(capacity: usize) -> Self {
        Self {
            buf: vec![0; capacity],
            head: 0,
            len: 0,
        }
    }

    /// Push a timestamp, overwriting the oldest if full.
    pub fn push(&mut self, ts: i64) {
        let cap = self.buf.len();
        if cap == 0 {
            return;
        }
        let write_pos = if self.len < cap {
            self.len
        } else {
            let pos = self.head;
            self.head = (self.head + 1) % cap;
            pos
        };
        if let Some(slot) = self.buf.get_mut(write_pos) {
            *slot = ts;
        }
        if self.len < cap {
            self.len += 1;
        }
    }

    /// Returns `true` when the buffer has reached its capacity.
    pub fn is_full(&self) -> bool {
        self.len == self.buf.len()
    }

    /// Returns the oldest timestamp, or `None` if empty.
    pub fn oldest(&self) -> Option<i64> {
        if self.len == 0 {
            return None;
        }
        self.buf.get(self.head).copied()
    }

    /// Returns the newest timestamp, or `None` if empty.
    pub fn newest(&self) -> Option<i64> {
        if self.len == 0 {
            return None;
        }
        let cap = self.buf.len();
        let idx = if self.len < cap {
            self.len - 1
        } else {
            (self.head + cap - 1) % cap
        };
        self.buf.get(idx).copied()
    }

    /// Check if the failure threshold is reached: buffer is full and the
    /// time span from oldest to newest is within `find_time` seconds.
    pub fn threshold_reached(&self, find_time: i64) -> bool {
        if !self.is_full() {
            return false;
        }
        match (self.oldest(), self.newest()) {
            (Some(old), Some(new)) => (new - old) < find_time,
            _ => false,
        }
    }

    /// Number of timestamps currently stored.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The total capacity.
    pub fn capacity(&self) -> usize {
        self.buf.len()
    }
}

#[cfg(test)]
mod tests {
    use crate::track::circular::CircularTimestamps;

    #[test]
    fn empty_buffer() {
        let buf = CircularTimestamps::new(3);
        assert!(buf.is_empty());
        assert!(!buf.is_full());
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.oldest(), None);
        assert_eq!(buf.newest(), None);
        assert!(!buf.threshold_reached(600));
    }

    #[test]
    fn push_until_full() {
        let mut buf = CircularTimestamps::new(3);
        buf.push(100);
        assert_eq!(buf.len(), 1);
        assert_eq!(buf.oldest(), Some(100));
        assert_eq!(buf.newest(), Some(100));

        buf.push(200);
        buf.push(300);
        assert!(buf.is_full());
        assert_eq!(buf.oldest(), Some(100));
        assert_eq!(buf.newest(), Some(300));
    }

    #[test]
    fn overwrites_oldest_when_full() {
        let mut buf = CircularTimestamps::new(3);
        buf.push(100);
        buf.push(200);
        buf.push(300);
        // Overwrite oldest (100)
        buf.push(400);
        assert!(buf.is_full());
        assert_eq!(buf.oldest(), Some(200));
        assert_eq!(buf.newest(), Some(400));

        // Overwrite 200
        buf.push(500);
        assert_eq!(buf.oldest(), Some(300));
        assert_eq!(buf.newest(), Some(500));
    }

    #[test]
    fn threshold_within_window() {
        let mut buf = CircularTimestamps::new(5);
        // 5 failures within 60 seconds
        for i in 0..5 {
            buf.push(1000 + i * 10);
        }
        assert!(buf.threshold_reached(600)); // 40s span < 600s window
        assert!(buf.threshold_reached(50)); // 40s span < 50s window
        assert!(!buf.threshold_reached(30)); // 40s span >= 30s window
    }

    #[test]
    fn threshold_not_full() {
        let mut buf = CircularTimestamps::new(5);
        buf.push(1000);
        buf.push(1001);
        // Only 2 of 5 — never triggers
        assert!(!buf.threshold_reached(600));
    }

    #[test]
    fn threshold_after_wrap() {
        let mut buf = CircularTimestamps::new(3);
        // Old failures far apart
        buf.push(100);
        buf.push(200);
        buf.push(300);
        // New burst
        buf.push(1000);
        buf.push(1001);
        // Buffer now has [300, 1000, 1001]
        assert_eq!(buf.oldest(), Some(300));
        assert!(buf.threshold_reached(800)); // 701s span < 800s
        assert!(!buf.threshold_reached(600)); // 701s span >= 600s
    }

    #[test]
    fn zero_capacity() {
        let mut buf = CircularTimestamps::new(0);
        buf.push(100); // should not panic
        assert!(buf.is_empty());
        assert_eq!(buf.capacity(), 0);
    }

    #[test]
    fn capacity_one() {
        let mut buf = CircularTimestamps::new(1);
        buf.push(100);
        assert!(buf.is_full());
        assert_eq!(buf.oldest(), Some(100));
        assert_eq!(buf.newest(), Some(100));
        // Any single entry trivially passes: new - old = 0 < any positive find_time
        assert!(buf.threshold_reached(1));

        buf.push(200);
        assert_eq!(buf.oldest(), Some(200));
        assert_eq!(buf.newest(), Some(200));
    }

    #[test]
    fn negative_timestamps() {
        let mut buf = CircularTimestamps::new(3);
        buf.push(-100);
        buf.push(-50);
        buf.push(-10);
        assert!(buf.is_full());
        assert_eq!(buf.oldest(), Some(-100));
        assert_eq!(buf.newest(), Some(-10));
        // Span is 90, which is < 200.
        assert!(buf.threshold_reached(200));
        assert!(!buf.threshold_reached(50));
    }

    #[test]
    fn threshold_with_find_time_zero() {
        let mut buf = CircularTimestamps::new(3);
        buf.push(100);
        buf.push(100);
        buf.push(100);
        // All same timestamp: new - old = 0, and find_time = 0: 0 < 0 is false.
        assert!(!buf.threshold_reached(0));
    }

    #[test]
    fn len_and_is_empty_through_lifecycle() {
        let mut buf = CircularTimestamps::new(2);
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);

        buf.push(1);
        assert!(!buf.is_empty());
        assert_eq!(buf.len(), 1);

        buf.push(2);
        assert_eq!(buf.len(), 2);

        // Overwrite — still full, len stays 2.
        buf.push(3);
        assert_eq!(buf.len(), 2);
        assert!(!buf.is_empty());
    }

    #[test]
    fn capacity_returns_correct_value() {
        let buf = CircularTimestamps::new(42);
        assert_eq!(buf.capacity(), 42);
    }
}
