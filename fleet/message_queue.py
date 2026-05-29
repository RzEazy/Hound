"""
Message Queue abstraction — NATS or Kafka backend for streaming telemetry and query results.

All collection layer data flows through the MQ rather than being processed inline,
enabling decoupled consumers, replay, and horizontal scaling.
"""

import json
import logging
import asyncio
from typing import Dict, Any, Callable, Optional, List
from dataclasses import dataclass
from abc import ABC, abstractmethod
from datetime import datetime

logger = logging.getLogger(__name__)


class MessageQueue(ABC):
    """Abstract message queue interface."""

    @abstractmethod
    async def connect(self):
        pass

    @abstractmethod
    async def disconnect(self):
        pass

    @abstractmethod
    def publish(self, topic: str, message: Dict[str, Any]):
        pass

    @abstractmethod
    async def subscribe(self, topic: str, callback: Callable[[Dict[str, Any]], None]):
        pass


class NATSQueue(MessageQueue):
    """
    NATS-based message queue implementation.
    
    NATS is preferred for HoundAI due to:
    - Low latency for real-time hunt steps
    - JetStream for persistence and replay
    - Simple deployment (single binary)
    - Subject-based routing (fleet.*, telemetry.*, hunt.*)
    """

    def __init__(self, servers: List[str] = None, credentials_path: Optional[str] = None):
        self.servers = servers or ["nats://localhost:4222"]
        self.credentials_path = credentials_path
        self._nc = None  # nats.aio.client.Client
        self._js = None  # JetStream context

    async def connect(self):
        """Connect to NATS cluster."""
        try:
            import nats
            self._nc = await nats.connect(
                servers=self.servers,
                max_reconnect_attempts=10,
            )
            self._js = self._nc.jetstream()
            # Ensure streams exist
            await self._ensure_streams()
            logger.info(f"Connected to NATS: {self.servers}")
        except Exception as e:
            logger.error(f"NATS connection failed: {e}")
            raise

    async def disconnect(self):
        if self._nc:
            await self._nc.drain()
            await self._nc.close()

    def publish(self, topic: str, message: Dict[str, Any]):
        """Publish message (sync wrapper for async publish)."""
        if not self._nc:
            logger.warning(f"NATS not connected, dropping message on {topic}")
            return
        payload = json.dumps(message, default=str).encode()
        # Fire-and-forget publish
        asyncio.create_task(self._nc.publish(topic, payload))

    async def publish_async(self, topic: str, message: Dict[str, Any]):
        """Async publish with JetStream acknowledgment."""
        if self._js:
            payload = json.dumps(message, default=str).encode()
            ack = await self._js.publish(topic, payload)
            return ack

    async def subscribe(self, topic: str, callback: Callable[[Dict[str, Any]], None]):
        """Subscribe to a topic with callback."""
        if not self._nc:
            raise RuntimeError("Not connected to NATS")

        async def _handler(msg):
            try:
                data = json.loads(msg.data.decode())
                callback(data)
            except Exception as e:
                logger.error(f"Error processing message on {topic}: {e}")

        await self._nc.subscribe(topic, cb=_handler)
        logger.info(f"Subscribed to: {topic}")

    async def subscribe_jetstream(self, topic: str, durable: str,
                                   callback: Callable[[Dict[str, Any]], None]):
        """Subscribe with JetStream for durable consumption."""
        if not self._js:
            raise RuntimeError("JetStream not available")

        async def _handler(msg):
            try:
                data = json.loads(msg.data.decode())
                callback(data)
                await msg.ack()
            except Exception as e:
                logger.error(f"JetStream handler error: {e}")
                await msg.nak()

        await self._js.subscribe(topic, durable=durable, cb=_handler)

    async def _ensure_streams(self):
        """Create required JetStream streams."""
        streams = [
            {"name": "FLEET", "subjects": ["fleet.>"]},
            {"name": "TELEMETRY", "subjects": ["telemetry.>"]},
            {"name": "HUNTS", "subjects": ["hunt.>"]},
        ]
        for stream_cfg in streams:
            try:
                await self._js.add_stream(**stream_cfg)
            except Exception:
                pass  # Stream may already exist


class KafkaQueue(MessageQueue):
    """
    Kafka-based message queue for high-throughput environments.
    
    Use Kafka when:
    - Fleet size > 10,000 nodes
    - Long-term event retention needed
    - Integration with existing Kafka infrastructure
    """

    def __init__(self, bootstrap_servers: List[str] = None):
        self.bootstrap_servers = bootstrap_servers or ["localhost:9092"]
        self._producer = None
        self._consumers: Dict[str, Any] = {}

    async def connect(self):
        """Connect Kafka producer."""
        try:
            from aiokafka import AIOKafkaProducer
            self._producer = AIOKafkaProducer(
                bootstrap_servers=self.bootstrap_servers,
                value_serializer=lambda v: json.dumps(v, default=str).encode(),
            )
            await self._producer.start()
            logger.info(f"Connected to Kafka: {self.bootstrap_servers}")
        except Exception as e:
            logger.error(f"Kafka connection failed: {e}")
            raise

    async def disconnect(self):
        if self._producer:
            await self._producer.stop()
        for consumer in self._consumers.values():
            await consumer.stop()

    def publish(self, topic: str, message: Dict[str, Any]):
        """Publish to Kafka topic."""
        if self._producer:
            asyncio.create_task(self._producer.send(topic, message))

    async def subscribe(self, topic: str, callback: Callable[[Dict[str, Any]], None]):
        """Subscribe to Kafka topic."""
        from aiokafka import AIOKafkaConsumer
        consumer = AIOKafkaConsumer(
            topic,
            bootstrap_servers=self.bootstrap_servers,
            value_deserializer=lambda v: json.loads(v.decode()),
            group_id="houndai-hunt-engine",
        )
        await consumer.start()
        self._consumers[topic] = consumer

        async def _consume():
            async for msg in consumer:
                callback(msg.value)

        asyncio.create_task(_consume())
