package kafka

import (
	"context"
	"errors"
	"log"
	"time"

	kafkago "github.com/segmentio/kafka-go"
)

var ErrQueueFull = errors.New("kafka queue full")

type Producer struct {
	writer   *kafkago.Writer
	topic    string
	messages chan []byte
}

func NewProducer(brokers []string, topic string) *Producer {
	producer := &Producer{
		writer: kafkago.NewWriter(kafkago.WriterConfig{
			Brokers: brokers,
			Topic:   topic,
		}),
		topic:    topic,
		messages: make(chan []byte, 100),
	}

	go producer.run()
	return producer
}

func (p *Producer) run() {
	for message := range p.messages {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := p.writer.WriteMessages(ctx, kafkago.Message{Value: message})
		cancel()

		if err != nil {
			log.Printf("failed to publish scan log to kafka: %v", err)
			continue
		}

		log.Printf("published scan log to kafka topic=%s bytes=%d", p.topic, len(message))
	}
}

func (p *Producer) Enqueue(data []byte) error {
	select {
	case p.messages <- data:
		return nil
	default:
		return ErrQueueFull
	}
}

func (p *Producer) Close() {
	close(p.messages)
	_ = p.writer.Close()
}
