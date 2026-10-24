// Message bus: Kafka in deployment, Redis Streams for development/tests (BUS=redis).
// Same topic names and JSON payloads either way.
package main

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/segmentio/kafka-go"
)

type Handler func(key string, value []byte)

type Bus interface {
	Subscribe(ctx context.Context, topic, group string, h Handler)
	Publish(ctx context.Context, topic, key string, value []byte) error
	Close() error
}

// ---------------------------------------------------------------- Kafka

type KafkaBus struct {
	brokers []string
	writer  *kafka.Writer
}

func NewKafkaBus(brokers string) *KafkaBus {
	bs := strings.Split(brokers, ",")
	return &KafkaBus{brokers: bs, writer: &kafka.Writer{
		Addr: kafka.TCP(bs...), Balancer: &kafka.Hash{}, BatchTimeout: 2 * time.Millisecond,
		RequiredAcks: kafka.RequireOne, AllowAutoTopicCreation: true}}
}

func (b *KafkaBus) Subscribe(ctx context.Context, topic, group string, h Handler) {
	r := kafka.NewReader(kafka.ReaderConfig{Brokers: b.brokers, Topic: topic, GroupID: group,
		MinBytes: 1, MaxBytes: 10e6, MaxWait: 5 * time.Millisecond, StartOffset: kafka.LastOffset})
	go func() {
		defer r.Close()
		for {
			m, err := r.ReadMessage(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				log.Printf("kafka read %s: %v", topic, err)
				time.Sleep(time.Second)
				continue
			}
			h(string(m.Key), m.Value)
		}
	}()
}

func (b *KafkaBus) Publish(ctx context.Context, topic, key string, value []byte) error {
	return b.writer.WriteMessages(ctx, kafka.Message{Topic: topic, Key: []byte(key), Value: value})
}

func (b *KafkaBus) Close() error { return b.writer.Close() }

// ---------------------------------------------------------------- Redis Streams

type RedisBus struct {
	rdb    *redis.Client
	maxLen int64
}

func NewRedisBus(rdb *redis.Client) *RedisBus { return &RedisBus{rdb: rdb, maxLen: 100000} }

func (b *RedisBus) Subscribe(ctx context.Context, topic, group string, h Handler) {
	stream := "bus:" + topic
	// "$" = only new messages, like Kafka's LastOffset for a new group
	if err := b.rdb.XGroupCreateMkStream(ctx, stream, group, "$").Err(); err != nil &&
		!strings.Contains(err.Error(), "BUSYGROUP") {
		log.Printf("redis group %s/%s: %v", stream, group, err)
	}
	consumer := group + "-1"
	go func() {
		for ctx.Err() == nil {
			res, err := b.rdb.XReadGroup(ctx, &redis.XReadGroupArgs{Group: group, Consumer: consumer,
				Streams: []string{stream, ">"}, Count: 100, Block: 50 * time.Millisecond}).Result()
			if err != nil {
				if err != redis.Nil && ctx.Err() == nil {
					log.Printf("redis read %s: %v", stream, err)
					time.Sleep(200 * time.Millisecond)
				}
				continue
			}
			for _, s := range res {
				for _, m := range s.Messages {
					k, _ := m.Values["key"].(string)
					v, _ := m.Values["value"].(string)
					h(k, []byte(v))
					b.rdb.XAck(ctx, stream, group, m.ID)
				}
			}
		}
	}()
}

func (b *RedisBus) Publish(ctx context.Context, topic, key string, value []byte) error {
	return b.rdb.XAdd(ctx, &redis.XAddArgs{Stream: "bus:" + topic, MaxLen: b.maxLen, Approx: true,
		Values: map[string]interface{}{"key": key, "value": string(value)}}).Err()
}

func (b *RedisBus) Close() error { return nil }
