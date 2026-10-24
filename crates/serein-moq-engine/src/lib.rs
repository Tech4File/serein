//! First-party in-memory media track/object fan-out with per-subscriber AND
//! global queued-byte bounds. Payload clones share an `Arc`, avoiding a full
//! encoded-frame copy per subscriber. This remains transport-agnostic: it is
//! NOT an MOQT wire implementation and opens no QUIC/WebTransport connection.
use std::{collections::{HashMap, VecDeque}, sync::Arc};

pub const TARGET_MOQT_DRAFT: &str = "draft-ietf-moq-transport-22";

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct TrackKey {
    pub namespace: String,
    pub name: String,
}

impl TrackKey {
    pub fn new(namespace: impl Into<String>, name: impl Into<String>) -> Result<Self, MoqError> {
        let namespace = namespace.into();
        let name = name.into();
        if namespace.is_empty()
            || name.is_empty()
            || namespace.len() > 512
            || name.len() > 256
            || !namespace.is_ascii()
            || !name.is_ascii()
        {
            return Err(MoqError::InvalidTrack);
        }
        Ok(Self { namespace, name })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MediaKind {
    Audio,
    Video,
    Data,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueuePolicy {
    /// Keep the newest live media by evicting this subscriber's oldest objects.
    RealtimeDropOldest,
    /// Preserve this subscriber's queued objects; reject new objects under pressure.
    ReliableReject,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectHeader {
    pub group: u64,
    pub subgroup: u64,
    pub sequence: u64,
    pub priority: u8,
}

/// The immutable encoded payload is shared across subscriber queues. The engine
/// accounts queued bytes per subscriber (a conservative backlog budget), while
/// avoiding an allocation/copy of the media bytes for every subscriber.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MediaObject {
    pub header: ObjectHeader,
    pub payload: Arc<[u8]>,
}

impl MediaObject {
    pub fn new(header: ObjectHeader, payload: impl Into<Arc<[u8]>>) -> Self {
        Self { header, payload: payload.into() }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PublishReport {
    pub subscribers: usize,
    pub enqueued: usize,
    pub dropped_oldest: usize,
    pub rejected_for_backpressure: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct EngineLimits {
    pub max_tracks: usize,
    pub max_subscriptions: usize,
    pub max_object_bytes: usize,
    pub max_queue_bytes_per_subscription: usize,
    /// Aggregate logical queued-byte budget across all subscribers.
    pub max_total_queue_bytes: usize,
    /// Prevent tiny/empty objects from creating an unbounded number of queue nodes.
    pub max_queue_objects_per_subscription: usize,
    /// Aggregate queue-node budget across all subscribers.
    pub max_total_queue_objects: usize,
}

impl Default for EngineLimits {
    fn default() -> Self {
        Self {
            max_tracks: 4096,
            max_subscriptions: 20_000,
            max_object_bytes: 2 * 1024 * 1024,
            max_queue_bytes_per_subscription: 4 * 1024 * 1024,
            max_total_queue_bytes: 64 * 1024 * 1024,
            max_queue_objects_per_subscription: 256,
            max_total_queue_objects: 131_072,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MoqError {
    InvalidTrack,
    TrackLimit,
    SubscriptionLimit,
    UnknownTrack,
    NotPublisher,
    DuplicateTrack,
    DuplicateSubscription,
    ObjectTooLarge,
    Backpressure,
    UnknownSubscription,
}

struct Track {
    publisher: u64,
    kind: MediaKind,
    subscriptions: Vec<u64>,
}

struct Subscription {
    subscriber: u64,
    track: TrackKey,
    policy: QueuePolicy,
    queue: VecDeque<MediaObject>,
    queued_bytes: usize,
}

pub struct MoqEngine {
    limits: EngineLimits,
    tracks: HashMap<TrackKey, Track>,
    subscriptions: HashMap<u64, Subscription>,
    queued_total_bytes: usize,
    queued_total_objects: usize,
}

fn subscription_would_exceed(sub: &Subscription, bytes: usize, limits: EngineLimits) -> bool {
    sub.queue.len().saturating_add(1) > limits.max_queue_objects_per_subscription
        || sub.queued_bytes.saturating_add(bytes) > limits.max_queue_bytes_per_subscription
}

fn engine_would_exceed(total_bytes: usize, total_objects: usize, bytes: usize, limits: EngineLimits) -> bool {
    total_bytes.saturating_add(bytes) > limits.max_total_queue_bytes
        || total_objects.saturating_add(1) > limits.max_total_queue_objects
}

impl MoqEngine {
    pub fn new(limits: EngineLimits) -> Self {
        Self {
            limits,
            tracks: HashMap::new(),
            subscriptions: HashMap::new(),
            queued_total_bytes: 0,
            queued_total_objects: 0,
        }
    }

    pub fn publish_track(
        &mut self,
        publisher: u64,
        key: TrackKey,
        kind: MediaKind,
    ) -> Result<(), MoqError> {
        if self.tracks.contains_key(&key) {
            return Err(MoqError::DuplicateTrack);
        }
        if self.tracks.len() >= self.limits.max_tracks {
            return Err(MoqError::TrackLimit);
        }
        self.tracks.insert(key, Track { publisher, kind, subscriptions: Vec::new() });
        Ok(())
    }

    /// The caller MUST authenticate and authorize the subscription against the
    /// Serein account/contact policy before invoking this in-memory engine.
    pub fn subscribe(
        &mut self,
        subscription_id: u64,
        subscriber: u64,
        track_key: &TrackKey,
        policy: QueuePolicy,
    ) -> Result<(), MoqError> {
        if self.subscriptions.contains_key(&subscription_id) {
            return Err(MoqError::DuplicateSubscription);
        }
        if self.subscriptions.len() >= self.limits.max_subscriptions {
            return Err(MoqError::SubscriptionLimit);
        }
        let track = self.tracks.get_mut(track_key).ok_or(MoqError::UnknownTrack)?;
        track.subscriptions.push(subscription_id);
        self.subscriptions.insert(
            subscription_id,
            Subscription {
                subscriber,
                track: track_key.clone(),
                policy,
                queue: VecDeque::new(),
                queued_bytes: 0,
            },
        );
        Ok(())
    }

    pub fn publish_object(
        &mut self,
        publisher: u64,
        track_key: &TrackKey,
        object: MediaObject,
    ) -> Result<PublishReport, MoqError> {
        let bytes = object.payload.len();
        if bytes > self.limits.max_object_bytes {
            return Err(MoqError::ObjectTooLarge);
        }
        if bytes > self.limits.max_total_queue_bytes {
            return Err(MoqError::Backpressure);
        }
        let track = self.tracks.get(track_key).ok_or(MoqError::UnknownTrack)?;
        if track.publisher != publisher {
            return Err(MoqError::NotPublisher);
        }
        let subscription_ids = track.subscriptions.clone();
        let mut report = PublishReport {
            subscribers: subscription_ids.len(),
            ..PublishReport::default()
        };

        for id in subscription_ids {
            let Some(sub) = self.subscriptions.get_mut(&id) else { continue };
            if sub.policy == QueuePolicy::ReliableReject
                && (subscription_would_exceed(sub, bytes, self.limits)
                    || engine_would_exceed(
                        self.queued_total_bytes,
                        self.queued_total_objects,
                        bytes,
                        self.limits,
                    ))
            {
                report.rejected_for_backpressure += 1;
                continue;
            }

            // Realtime subscribers evict only their own oldest objects. They do
            // not silently destroy another subscriber's queued media to get room.
            while sub.policy == QueuePolicy::RealtimeDropOldest
                && !sub.queue.is_empty()
                && (subscription_would_exceed(sub, bytes, self.limits)
                    || engine_would_exceed(
                        self.queued_total_bytes,
                        self.queued_total_objects,
                        bytes,
                        self.limits,
                    ))
            {
                if let Some(old) = sub.queue.pop_front() {
                    let old_bytes = old.payload.len();
                    sub.queued_bytes = sub.queued_bytes.saturating_sub(old_bytes);
                    self.queued_total_bytes = self.queued_total_bytes.saturating_sub(old_bytes);
                    self.queued_total_objects = self.queued_total_objects.saturating_sub(1);
                    report.dropped_oldest += 1;
                }
            }

            if !subscription_would_exceed(sub, bytes, self.limits)
                && !engine_would_exceed(
                    self.queued_total_bytes,
                    self.queued_total_objects,
                    bytes,
                    self.limits,
                )
            {
                sub.queued_bytes += bytes;
                self.queued_total_bytes += bytes;
                self.queued_total_objects += 1;
                sub.queue.push_back(object.clone()); // Arc clone; media bytes are not copied.
                report.enqueued += 1;
            } else {
                report.rejected_for_backpressure += 1;
            }
        }
        Ok(report)
    }

    pub fn next_object(
        &mut self,
        subscription_id: u64,
    ) -> Result<Option<MediaObject>, MoqError> {
        let sub = self.subscriptions.get_mut(&subscription_id).ok_or(MoqError::UnknownSubscription)?;
        let next = sub.queue.pop_front();
        if let Some(ref object) = next {
            let bytes = object.payload.len();
            sub.queued_bytes = sub.queued_bytes.saturating_sub(bytes);
            self.queued_total_bytes = self.queued_total_bytes.saturating_sub(bytes);
            self.queued_total_objects = self.queued_total_objects.saturating_sub(1);
        }
        Ok(next)
    }

    pub fn unsubscribe(&mut self, subscription_id: u64) -> Result<(), MoqError> {
        let sub = self.subscriptions.remove(&subscription_id).ok_or(MoqError::UnknownSubscription)?;
        self.queued_total_bytes = self.queued_total_bytes.saturating_sub(sub.queued_bytes);
        self.queued_total_objects = self.queued_total_objects.saturating_sub(sub.queue.len());
        if let Some(track) = self.tracks.get_mut(&sub.track) {
            track.subscriptions.retain(|id| *id != subscription_id);
        }
        Ok(())
    }

    pub fn unpublish_track(&mut self, publisher: u64, key: &TrackKey) -> Result<usize, MoqError> {
        let track = self.tracks.get(key).ok_or(MoqError::UnknownTrack)?;
        if track.publisher != publisher {
            return Err(MoqError::NotPublisher);
        }
        let subscriptions = track.subscriptions.clone();
        for id in &subscriptions {
            if let Some(sub) = self.subscriptions.remove(id) {
                self.queued_total_bytes = self.queued_total_bytes.saturating_sub(sub.queued_bytes);
                self.queued_total_objects = self.queued_total_objects.saturating_sub(sub.queue.len());
            }
        }
        self.tracks.remove(key);
        Ok(subscriptions.len())
    }

    pub fn track_kind(&self, key: &TrackKey) -> Option<MediaKind> {
        self.tracks.get(key).map(|track| track.kind)
    }

    pub fn subscription_owner(&self, id: u64) -> Option<u64> {
        self.subscriptions.get(&id).map(|sub| sub.subscriber)
    }

    /// Approximate aggregate queued-byte accounting, useful for admission control
    /// and metrics. It is conservative when subscribers share an `Arc` payload.
    pub fn queued_total_bytes(&self) -> usize {
        self.queued_total_bytes
    }

    pub fn queued_total_objects(&self) -> usize {
        self.queued_total_objects
    }
}

impl Default for MoqEngine {
    fn default() -> Self {
        Self::new(EngineLimits::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> TrackKey {
        TrackKey::new("user/alice/call-1", "audio").unwrap()
    }

    fn object(sequence: u64, size: usize) -> MediaObject {
        MediaObject::new(
            ObjectHeader { group: 0, subgroup: 0, sequence, priority: 1 },
            vec![7; size],
        )
    }

    fn limits(max_sub: usize, max_total: usize) -> EngineLimits {
        EngineLimits {
            max_tracks: 4,
            max_subscriptions: 4,
            max_object_bytes: 32,
            max_queue_bytes_per_subscription: max_sub,
            max_total_queue_bytes: max_total,
            max_queue_objects_per_subscription: 8,
            max_total_queue_objects: 16,
        }
    }

    #[test]
    fn publish_subscribe_routes_objects_in_order() {
        let mut engine = MoqEngine::default();
        let track = key();
        engine.publish_track(7, track.clone(), MediaKind::Audio).unwrap();
        engine.subscribe(9, 10, &track, QueuePolicy::RealtimeDropOldest).unwrap();
        let report = engine.publish_object(7, &track, object(1, 16)).unwrap();
        assert_eq!(report.enqueued, 1);
        assert_eq!(engine.next_object(9).unwrap().unwrap().header.sequence, 1);
        assert_eq!(engine.queued_total_bytes(), 0);
        assert_eq!(engine.queued_total_objects(), 0);
    }

    #[test]
    fn realtime_queue_drops_oldest_to_respect_per_subscriber_limit() {
        let mut engine = MoqEngine::new(limits(24, 64));
        let track = key();
        engine.publish_track(7, track.clone(), MediaKind::Video).unwrap();
        engine.subscribe(9, 10, &track, QueuePolicy::RealtimeDropOldest).unwrap();
        engine.publish_object(7, &track, object(1, 16)).unwrap();
        let report = engine.publish_object(7, &track, object(2, 16)).unwrap();
        assert_eq!(report.dropped_oldest, 1);
        assert_eq!(engine.next_object(9).unwrap().unwrap().header.sequence, 2);
        assert_eq!(engine.queued_total_bytes(), 0);
    }

    #[test]
    fn reliable_subscriber_rejects_without_blocking_realtime_subscriber() {
        let mut engine = MoqEngine::new(limits(16, 64));
        let track = key();
        engine.publish_track(7, track.clone(), MediaKind::Data).unwrap();
        engine.subscribe(9, 10, &track, QueuePolicy::ReliableReject).unwrap();
        engine.subscribe(10, 11, &track, QueuePolicy::RealtimeDropOldest).unwrap();
        engine.publish_object(7, &track, object(1, 16)).unwrap();
        let report = engine.publish_object(7, &track, object(2, 16)).unwrap();
        assert_eq!(report.rejected_for_backpressure, 1);
        assert_eq!(report.dropped_oldest, 1);
        assert_eq!(report.enqueued, 1);
    }

    #[test]
    fn global_queue_budget_is_enforced_and_released_on_unsubscribe() {
        let mut engine = MoqEngine::new(limits(32, 16));
        let track = key();
        engine.publish_track(7, track.clone(), MediaKind::Data).unwrap();
        engine.subscribe(9, 10, &track, QueuePolicy::ReliableReject).unwrap();
        engine.subscribe(10, 11, &track, QueuePolicy::ReliableReject).unwrap();
        let report = engine.publish_object(7, &track, object(1, 16)).unwrap();
        assert_eq!(report.enqueued, 1);
        assert_eq!(report.rejected_for_backpressure, 1);
        assert_eq!(engine.queued_total_bytes(), 16);
        engine.unsubscribe(9).unwrap();
        assert_eq!(engine.queued_total_bytes(), 0);
        assert_eq!(engine.queued_total_objects(), 0);
        let report = engine.publish_object(7, &track, object(2, 16)).unwrap();
        assert_eq!(report.enqueued, 1);
    }

    #[test]
    fn global_pressure_drops_only_this_realtime_subscribers_oldest() {
        let mut engine = MoqEngine::new(limits(32, 32));
        let first = key();
        let second = TrackKey::new("user/alice/call-1", "video").unwrap();
        engine.publish_track(7, first.clone(), MediaKind::Audio).unwrap();
        engine.publish_track(7, second.clone(), MediaKind::Video).unwrap();
        engine.subscribe(9, 10, &first, QueuePolicy::RealtimeDropOldest).unwrap();
        engine.subscribe(10, 11, &second, QueuePolicy::ReliableReject).unwrap();
        engine.publish_object(7, &first, object(1, 16)).unwrap();
        engine.publish_object(7, &second, object(2, 16)).unwrap();
        let report = engine.publish_object(7, &first, object(3, 16)).unwrap();
        assert_eq!(report.dropped_oldest, 1);
        assert_eq!(report.enqueued, 1);
        assert_eq!(engine.queued_total_bytes(), 32);
        assert_eq!(engine.next_object(10).unwrap().unwrap().header.sequence, 2);
    }

    #[test]
    fn zero_byte_objects_are_bounded_by_queue_node_limits() {
        let engine_limits = EngineLimits {
            max_queue_objects_per_subscription: 2,
            max_total_queue_objects: 4,
            ..limits(32, 64)
        };
        let mut engine = MoqEngine::new(engine_limits);
        let track = key();
        engine.publish_track(7, track.clone(), MediaKind::Data).unwrap();
        engine.subscribe(9, 10, &track, QueuePolicy::ReliableReject).unwrap();
        assert_eq!(engine.publish_object(7, &track, object(1, 0)).unwrap().enqueued, 1);
        assert_eq!(engine.publish_object(7, &track, object(2, 0)).unwrap().enqueued, 1);
        let report = engine.publish_object(7, &track, object(3, 0)).unwrap();
        assert_eq!(report.rejected_for_backpressure, 1);
        assert_eq!(engine.queued_total_bytes(), 0);
        assert_eq!(engine.queued_total_objects(), 2);
        engine.next_object(9).unwrap();
        assert_eq!(engine.publish_object(7, &track, object(4, 0)).unwrap().enqueued, 1);
    }

    #[test]
    fn shared_payload_is_not_duplicated_for_subscribers() {
        let mut engine = MoqEngine::new(limits(64, 128));
        let track = key();
        engine.publish_track(7, track.clone(), MediaKind::Video).unwrap();
        engine.subscribe(9, 10, &track, QueuePolicy::ReliableReject).unwrap();
        engine.subscribe(10, 11, &track, QueuePolicy::ReliableReject).unwrap();
        let media = object(4, 16);
        engine.publish_object(7, &track, media.clone()).unwrap();
        let first = engine.next_object(9).unwrap().unwrap();
        let second = engine.next_object(10).unwrap().unwrap();
        assert!(Arc::ptr_eq(&first.payload, &second.payload));
        assert!(Arc::ptr_eq(&first.payload, &media.payload));
        assert_eq!(engine.queued_total_bytes(), 0);
    }

    #[test]
    fn only_track_owner_can_publish_and_objects_are_bounded() {
        let mut engine = MoqEngine::new(limits(8, 16));
        let track = key();
        engine.publish_track(7, track.clone(), MediaKind::Audio).unwrap();
        assert_eq!(engine.publish_object(8, &track, object(1, 1)), Err(MoqError::NotPublisher));
        assert_eq!(engine.publish_object(7, &track, object(1, 33)), Err(MoqError::ObjectTooLarge));
    }

    #[test]
    fn unpublishing_releases_all_subscriber_queue_accounting() {
        let mut engine = MoqEngine::new(limits(64, 128));
        let track = key();
        engine.publish_track(7, track.clone(), MediaKind::Audio).unwrap();
        engine.subscribe(9, 10, &track, QueuePolicy::ReliableReject).unwrap();
        engine.subscribe(10, 11, &track, QueuePolicy::ReliableReject).unwrap();
        engine.publish_object(7, &track, object(1, 16)).unwrap();
        assert_eq!(engine.queued_total_bytes(), 32);
        assert_eq!(engine.unpublish_track(7, &track).unwrap(), 2);
        assert_eq!(engine.queued_total_bytes(), 0);
        assert_eq!(engine.queued_total_objects(), 0);
        assert!(engine.next_object(9).is_err());
    }
}
